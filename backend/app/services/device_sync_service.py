"""
Real-Time Device Synchronization & Pairing Service for PhishGuard AI.
Handles laptop-to-Android pairing, SSE event streaming, and live scan broadcasting.
"""

import asyncio
import json
import secrets
import string
from datetime import datetime, timezone
from typing import Dict, List, Set, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.qr_scan import PairedDevice, QRScan
from app.models.user import User


class DeviceSyncManager:
    def __init__(self):
        # Maps user_id -> Set of asyncio.Queue instances for SSE subscribers
        self._user_queues: Dict[int, Set[asyncio.Queue]] = {}
        # Ephemeral pairing codes store: code -> {"user_id": int, "expires_at": float}
        self._pending_pairings: Dict[str, Dict[str, Any]] = {}
        # Latest scan cache per user: user_id -> scan_dict
        self._latest_scans: Dict[int, Dict[str, Any]] = {}

    def generate_pairing_code(self, user_id: int) -> Dict[str, Any]:
        """Generate a secure 6-digit pairing code and QR pairing payload."""
        digits = "".join(secrets.choice(string.digits) for _ in range(6))
        token = secrets.token_urlsafe(32)
        
        expires_at = datetime.now(timezone.utc).timestamp() + 600  # 10 mins
        
        self._pending_pairings[digits] = {
            "user_id": user_id,
            "token": token,
            "expires_at": expires_at
        }

        pairing_payload = {
            "version": "1.0",
            "server_url": "http://localhost:8000/api/v1",
            "pairing_code": digits,
            "token": token,
            "user_id": user_id,
            "expires_at": expires_at
        }

        return {
            "pairing_code": digits,
            "expires_in_seconds": 600,
            "pairing_qr_payload": json.dumps(pairing_payload),
            "token": token
        }

    async def register_device(
        self,
        db: AsyncSession,
        pairing_code: str,
        device_name: str,
        device_id: str,
        device_type: str = "android"
    ) -> Optional[PairedDevice]:
        """Validate pairing code and persist paired device to database."""
        pending = self._pending_pairings.get(pairing_code)
        if not pending:
            return None
        
        if datetime.now(timezone.utc).timestamp() > pending["expires_at"]:
            del self._pending_pairings[pairing_code]
            return None

        user_id = pending["user_id"]
        auth_token = pending["token"]

        # Check existing device_id for this user
        result = await db.execute(
            select(PairedDevice).where(PairedDevice.device_id == device_id)
        )
        device = result.scalar_one_or_none()

        if device:
            device.user_id = user_id
            device.device_name = device_name
            device.auth_token = auth_token
            device.is_active = True
            device.last_seen = datetime.now(timezone.utc)
        else:
            device = PairedDevice(
                user_id=user_id,
                device_name=device_name,
                device_type=device_type,
                device_id=device_id,
                pairing_code=pairing_code,
                auth_token=auth_token,
                is_active=True,
                notification_enabled=True,
                min_notify_severity="SUSPICIOUS",
                last_seen=datetime.now(timezone.utc)
            )
            db.add(device)

        await db.commit()
        await db.refresh(device)

        # Clear used code
        self._pending_pairings.pop(pairing_code, None)

        # Notify active clients that a device was paired
        await self.broadcast_event(user_id, {
            "event_type": "DEVICE_PAIRED",
            "device": {
                "id": device.id,
                "name": device.device_name,
                "type": device.device_type,
                "paired_at": device.created_at.isoformat()
            }
        })

        return device

    def subscribe(self, user_id: int) -> asyncio.Queue:
        """Register a new SSE stream queue for real-time push."""
        queue: asyncio.Queue = asyncio.Queue()
        if user_id not in self._user_queues:
            self._user_queues[user_id] = set()
        self._user_queues[user_id].add(queue)
        return queue

    def unsubscribe(self, user_id: int, queue: asyncio.Queue):
        """Clean up disconnected SSE stream queue."""
        if user_id in self._user_queues:
            self._user_queues[user_id].discard(queue)
            if not self._user_queues[user_id]:
                del self._user_queues[user_id]

    async def broadcast_scan(self, user_id: int, scan_data: Dict[str, Any]):
        """Broadcast new QR threat scan event to all connected Android apps & dashboards."""
        self._latest_scans[user_id] = scan_data
        
        event_message = {
            "event_type": "QR_SCAN_COMPLETED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan": scan_data
        }
        await self.broadcast_event(user_id, event_message)

    async def broadcast_event(self, user_id: int, payload: Dict[str, Any]):
        """Push arbitrary real-time event to a user's subscriber queues."""
        queues = self._user_queues.get(user_id, set()).copy()
        for q in queues:
            try:
                await q.put(payload)
            except Exception:
                pass

    def get_latest_scan(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self._latest_scans.get(user_id)


device_sync_manager = DeviceSyncManager()
