"""
Document Database Manager (MongoDB Motor Async).
Provides async access to MongoDB Atlas / Local MongoDB collections:
- scan_raw_data
- shap_explanations
- chatbot_conversations
- adaptive_learning_logs
- community_intel_raw
Includes an intelligent in-memory fallback mock database when MongoDB server is not running locally.
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid

logger = logging.getLogger("phishguard.mongodb")

try:
    from motor.motor_asyncio import AsyncIOMotorClient
    HAS_MOTOR = True
except ImportError:
    HAS_MOTOR = False


class InMemoryCollection:
    """Mock MongoDB collection that stores documents in-memory when MongoDB daemon is offline."""
    def __init__(self, name: str):
        self.name = name
        self.docs: Dict[str, Dict[str, Any]] = {}

    async def insert_one(self, doc: Dict[str, Any]) -> Any:
        doc_copy = dict(doc)
        if "_id" not in doc_copy:
            doc_copy["_id"] = str(uuid.uuid4())
        else:
            doc_copy["_id"] = str(doc_copy["_id"])
        self.docs[doc_copy["_id"]] = doc_copy
        
        class InsertResult:
            inserted_id = doc_copy["_id"]
        return InsertResult()

    async def find_one(self, filter_query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for doc in self.docs.values():
            match = True
            for k, v in filter_query.items():
                if doc.get(k) != v:
                    match = False
                    break
            if match:
                return dict(doc)
        return None

    def find(self, filter_query: Optional[Dict[str, Any]] = None) -> Any:
        class AsyncCursor:
            def __init__(self, docs_list: List[Dict[str, Any]]):
                self.docs_list = docs_list
                self.index = 0

            def sort(self, key: str, direction: int = -1):
                reverse = direction == -1
                self.docs_list.sort(key=lambda x: str(x.get(key, "")), reverse=reverse)
                return self

            def limit(self, n: int):
                self.docs_list = self.docs_list[:n]
                return self

            async def to_list(self, length: Optional[int] = None) -> List[Dict[str, Any]]:
                if length is not None:
                    return [dict(d) for d in self.docs_list[:length]]
                return [dict(d) for d in self.docs_list]

            def __aiter__(self):
                self.index = 0
                return self

            async def __anext__(self):
                if self.index < len(self.docs_list):
                    res = self.docs_list[self.index]
                    self.index += 1
                    return dict(res)
                raise StopAsyncIteration

        results = []
        filter_q = filter_query or {}
        for doc in self.docs.values():
            match = True
            for k, v in filter_q.items():
                if doc.get(k) != v:
                    match = False
                    break
            if match:
                results.append(doc)
        return AsyncCursor(results)

    async def update_one(self, filter_query: Dict[str, Any], update_data: Dict[str, Any], upsert: bool = False) -> Any:
        existing = await self.find_one(filter_query)
        if existing:
            doc_id = existing["_id"]
            set_data = update_data.get("$set", update_data)
            self.docs[doc_id].update(set_data)
        elif upsert:
            new_doc = dict(filter_query)
            new_doc.update(update_data.get("$set", update_data))
            await self.insert_one(new_doc)

    async def count_documents(self, filter_query: Optional[Dict[str, Any]] = None) -> int:
        cursor = self.find(filter_query)
        res = await cursor.to_list(100000)
        return len(res)


class InMemoryMongoDB:
    """Mock MongoDB Database container."""
    def __init__(self, name: str = "phishguard_unstructured"):
        self.name = name
        self.collections: Dict[str, InMemoryCollection] = {}

    def __getitem__(self, name: str) -> InMemoryCollection:
        if name not in self.collections:
            self.collections[name] = InMemoryCollection(name)
        return self.collections[name]


class MongoDBManager:
    client: Optional[Any] = None
    db: Optional[Any] = None
    is_fallback: bool = False

    async def connect(self, uri: str, db_name: str):
        if HAS_MOTOR and uri:
            try:
                import asyncio
                client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=800)
                await asyncio.wait_for(client.admin.command('ping'), timeout=0.8)
                self.client = client
                self.db = self.client[db_name]
                self.is_fallback = False
                logger.info(f"Connected successfully to MongoDB at {uri}")
                return
            except Exception as e:
                logger.info(f"MongoDB offline ({e}). Using resilient in-memory document store.")
        
        self.db = InMemoryMongoDB(db_name)
        self.is_fallback = True
        logger.info("Using in-memory fallback MongoDB store for unstructured scan payloads and explanations.")

    async def close(self):
        if self.client and not self.is_fallback:
            self.client.close()


mongo_manager = MongoDBManager()


async def get_mongo_db() -> Any:
    """FastAPI dependency yielding MongoDB database instance."""
    return mongo_manager.db
