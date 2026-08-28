"""
Device Pairing & Real-Time Sync Routes (/api/v1/devices).
Enables secure Laptop <-> Android device pairing and Server-Sent Events (SSE) live streaming.
"""

import asyncio
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete

from app.db.mysql import get_db
from app.models.user import User
from app.models.qr_scan import PairedDevice
from app.schemas.qr_threat import (
    PairingRequestResponse,
    PairingConfirmRequest,
    PairedDeviceResponse
)
from app.services.device_sync_service import device_sync_manager
from app.core.dependencies import get_current_user, get_optional_user

router = APIRouter(prefix="/devices", tags=["Device Pairing & Sync"])


@router.post("/pair/request", response_model=PairingRequestResponse)
async def request_device_pairing(
    current_user: User = Depends(get_current_user)
):
    """Generate a one-time 6-digit pairing code and QR pairing payload for Android companion."""
    pairing_info = device_sync_manager.generate_pairing_code(current_user.id)
    return PairingRequestResponse(**pairing_info)


@router.post("/pair/confirm", response_model=dict)
async def confirm_device_pairing(
    req: PairingConfirmRequest,
    db: AsyncSession = Depends(get_db)
):
    """Pair Android companion app using the 6-digit pairing code."""
    device = await device_sync_manager.register_device(
        db=db,
        pairing_code=req.pairing_code,
        device_name=req.device_name,
        device_id=req.device_id,
        device_type=req.device_type
    )
    if not device:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired pairing code. Please generate a fresh code on your laptop."
        )

    return {
        "status": "success",
        "message": "Device paired successfully with PhishGuard AI laptop shield.",
        "device": {
            "id": device.id,
            "device_name": device.device_name,
            "user_id": device.user_id,
            "auth_token": device.auth_token
        }
    }


@router.get("/", response_model=List[PairedDeviceResponse])
async def list_paired_devices(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all registered Android / companion devices for the authenticated user."""
    result = await db.execute(
        select(PairedDevice).where(PairedDevice.user_id == current_user.id)
    )
    devices = result.scalars().all()
    return [PairedDeviceResponse.model_validate(d) for d in devices]


@router.delete("/{device_id}", response_model=dict)
async def unpair_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Unpair and revoke access for an Android companion device."""
    await db.execute(
        delete(PairedDevice).where(
            PairedDevice.device_id == device_id,
            PairedDevice.user_id == current_user.id
        )
    )
    await db.commit()
    return {"status": "success", "message": f"Device {device_id} unpaired successfully."}


@router.get("/latest-scan", response_model=dict)
async def get_latest_scan(
    current_user: User = Depends(get_current_user)
):
    """Fetch latest QR scan for quick initial Android dashboard sync."""
    latest = device_sync_manager.get_latest_scan(current_user.id)
    return {"latest_scan": latest}


@router.get("/events")
async def stream_device_events(
    request: Request,
    token: Optional[str] = None,
    current_user: User = Depends(get_optional_user)
):
    """
    Server-Sent Events (SSE) streaming endpoint:
    Pushes live QR threat detection events, critical alerts, and pairing updates
    directly to Android Companion App and Web Dashboard.
    """
    user_id = current_user.id if current_user else 1
    queue = device_sync_manager.subscribe(user_id)

    async def event_generator():
        try:
            # Send initial connected handshake
            yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'user_id': user_id})}\n\n"
            
            # Send latest scan if available
            latest = device_sync_manager.get_latest_scan(user_id)
            if latest:
                yield f"event: QR_SCAN_COMPLETED\ndata: {json.dumps({'event_type': 'QR_SCAN_COMPLETED', 'scan': latest})}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20.0)
                    event_type = event.get("event_type", "message")
                    yield f"event: {event_type}\ndata: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Send keep-alive heartbeat ping
                    yield f": ping\n\n"
        finally:
            device_sync_manager.unsubscribe(user_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
