# amnesiadb.py (Version 3.1)
# AmnesiaDB: A Multi-Tenant, Secure, In-Memory Data Store with FastAPI
# Now with Webhooks, Dashboard, Python-native features, and Advanced Querying
import argparse
import asyncio
import base64
import fnmatch
import heapq
import json
import os
import pickle
import secrets
import textwrap
import time
from contextlib import asynccontextmanager
from typing import Any, Callable, Dict, List, Optional, Tuple

import aiosqlite
import httpx
import uvicorn
from fastapi import (Depends, FastAPI, HTTPException, Query, Request, Security,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security.api_key import APIKeyHeader
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field


DATABASES: Dict[str, "DatabaseInstance"] = {}
GLOBAL_DB_LOCK = asyncio.Lock()
ADMIN_DB_FILE = "amnesiadb_admin.db"
HTTP_CLIENT = httpx.AsyncClient()

API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

templates = Jinja2Templates(directory="templates")



class CommandRequest(BaseModel):
    command: str = Field(..., description="The command to execute (e.g., 'SET', 'GET', 'LPUSH').")
    args: List[Any] = Field([], description="A list of arguments for the command.")

class CreateDbRequest(BaseModel):
    snapshot_interval: int = Field(60, gt=0, description="Interval in seconds for snapshotting to disk.")

class CreateKeyRequest(BaseModel):
    permissions: str = Field("read", pattern="^(read|write|admin)$", description="Permissions for the new key: 'read', 'write', or 'admin'.")

class UpdateConfigRequest(BaseModel):
    snapshot_interval: int = Field(..., gt=0, description="New interval in seconds for snapshotting.")

class PublishRequest(BaseModel):
    message: str

class WebhookRequest(BaseModel):
    key_pattern: str = Field(..., description="Glob-style pattern for keys (e.g., 'user:*:status').")
    url: str = Field(..., description="The HTTP POST endpoint to call on an event.")

class FunctionUploadRequest(BaseModel):
    code: str = Field(..., description="The Python source code of the function to upload.")


API_KEYS: Dict[str, Dict[str, str]] = {}

def generate_api_key():
    return secrets.token_urlsafe(32)

async def setup_admin_db():
    async with aiosqlite.connect(ADMIN_DB_FILE) as db:
        await db.execute("CREATE TABLE IF NOT EXISTS api_keys (api_key TEXT PRIMARY KEY, db_name TEXT NOT NULL, permissions TEXT NOT NULL)")
        await db.execute("CREATE TABLE IF NOT EXISTS databases (db_name TEXT PRIMARY KEY, snapshot_interval INTEGER NOT NULL)")
        await db.commit()

async def load_keys_from_db():
    async with aiosqlite.connect(ADMIN_DB_FILE) as db:
        async with db.execute("SELECT api_key, db_name, permissions FROM api_keys") as cursor:
            async for row in cursor:
                API_KEYS[row[0]] = {"db_name": row[1], "permissions": row[2]}

async def get_db_and_auth(db_name: str, api_key: str = Security(api_key_header)) -> Tuple["DatabaseInstance", str]:
    key_info = API_KEYS.get(api_key)
    if not key_info or key_info["db_name"] != db_name:
        raise HTTPException(status_code=403, detail="Invalid or unauthorized API Key")
    db_instance = DATABASES.get(db_name)
    if not db_instance:
        raise HTTPException(status_code=404, detail=f"Database '{db_name}' not found.")
    return db_instance, key_info["permissions"]

async def get_db_for_ws(db_name: str, token: str = Query(...)) -> "DatabaseInstance":
    key_info = API_KEYS.get(token)
    if not key_info or key_info["db_name"] != db_name:
        raise HTTPException(status_code=403, detail="Invalid or unauthorized API Token")
    db_instance = DATABASES.get(db_name)
    if not db_instance:
        raise HTTPException(status_code=404, detail=f"Database '{db_name}' not found.")
    return db_instance


class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, Dict[str, List[WebSocket]]] = {}
    async def connect(self, db_name: str, channel: str, websocket: WebSocket):
        await websocket.accept()
        self.connections.setdefault(db_name, {}).setdefault(channel, []).append(websocket)
    def disconnect(self, db_name: str, channel: str, websocket: WebSocket):
        if db_name in self.connections and channel in self.connections[db_name]:
            self.connections[db_name][channel].remove(websocket)
            if not self.connections[db_name][channel]: del self.connections[db_name][channel]
            if not self.connections[db_name]: del self.connections[db_name]
    async def broadcast(self, db_name: str, channel: str, message: str):
        if db_name in self.connections and channel in self.connections[db_name]:
            for connection in self.connections[db_name][channel]:
                await connection.send_text(message)

pubsub_manager = ConnectionManager()

class DatabaseInstance:
    def __init__(self, name: str, snapshot_interval: int):
        self.name = name
        self.db_file = f"{name}.db"
        self.snapshot_interval = snapshot_interval
        self.store: Dict[str, Dict[str, Any]] = {}
        self.expirations: Dict[str, float] = {}
        self.lock = asyncio.Lock()
        self.snapshot_task: Optional[asyncio.Task] = None
        self.ttl_check_task: Optional[asyncio.Task] = None
        self.webhooks: Dict[int, Dict[str, str]] = {}
        self.user_functions: Dict[str, Callable] = {}
        self.fts_conn: Optional[aiosqlite.Connection] = None
        self.webhook_queue = asyncio.Queue()
        self.webhook_worker_task: Optional[asyncio.Task] = None

    async def initialize(self):
        await self._init_db_schema()
        await self._init_fts()
        await self._load_webhooks()
        await self.load_from_disk()
        await self.start_background_tasks()

    async def _init_db_schema(self):
        async with aiosqlite.connect(self.db_file) as db:
            await db.execute("CREATE TABLE IF NOT EXISTS strings (key TEXT PRIMARY KEY, value TEXT, expires_at REAL)")
            await db.execute("CREATE TABLE IF NOT EXISTS lists (key TEXT, idx INTEGER, value TEXT, PRIMARY KEY (key, idx))")
            await db.execute("CREATE TABLE IF NOT EXISTS hashes (key TEXT, field TEXT, value TEXT, PRIMARY KEY (key, field))")
            await db.execute("CREATE TABLE IF NOT EXISTS sets (key TEXT, member TEXT, PRIMARY KEY (key, member))")
            await db.execute("CREATE TABLE IF NOT EXISTS sorted_sets (key TEXT, member TEXT, score REAL, PRIMARY KEY (key, member))")
            await db.execute("CREATE TABLE IF NOT EXISTS webhooks (id INTEGER PRIMARY KEY AUTOINCREMENT, key_pattern TEXT NOT NULL, url TEXT NOT NULL)")
            await db.commit()

    async def _init_fts(self):
        self.fts_conn = await aiosqlite.connect(":memory:")
        await self.fts_conn.execute("CREATE VIRTUAL TABLE strings_fts USING fts5(key, value)")
        await self.fts_conn.commit()

    async def _load_webhooks(self):
        async with aiosqlite.connect(self.db_file) as db:
            async with db.execute("SELECT id, key_pattern, url FROM webhooks") as cursor:
                async for row in cursor:
                    self.webhooks[row[0]] = {"key_pattern": row[1], "url": row[2]}

    async def trigger_webhook(self, event: str, key: str, **kwargs):
        payload = {"event": event, "db_name": self.name, "key": key, "timestamp": time.time(), **kwargs}
        for hook in self.webhooks.values():
            if fnmatch.fnmatch(key, hook["key_pattern"]):
                await self.webhook_queue.put({"url": hook["url"], "payload": payload})

    async def _webhook_worker(self):
        while True:
            try:
                task = await self.webhook_queue.get()
                try:
                    await HTTP_CLIENT.post(task["url"], json=task["payload"], timeout=5.0)
                except httpx.RequestError as e:
                    print(f"[{self.name}] Webhook request failed for URL {task['url']}: {e}")
                finally:
                    self.webhook_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[{self.name}] Error in webhook worker: {e}")

    async def load_from_disk(self):
        async with self.lock:
            self.store.clear()
            self.expirations.clear()
            async with aiosqlite.connect(self.db_file) as db:
                now = time.time()
                
                # First, get all expirations so we can filter expired complex types
                async with db.execute("SELECT key, expires_at FROM strings WHERE expires_at IS NOT NULL") as cursor:
                    async for key, expires_at in cursor:
                        if expires_at and expires_at > now:
                            self.expirations[key] = expires_at

                # Load Strings
                async with db.execute("SELECT key, value, expires_at FROM strings") as cursor:
                    async for key, value, expires_at in cursor:
                        if expires_at and expires_at <= now: continue
                        if value is not None:
                            self.store[key] = {"type": "string", "value": value}
                            await self.fts_conn.execute("INSERT INTO strings_fts (key, value) VALUES (?, ?)", (key, value))
                await self.fts_conn.commit()

                # Load Lists
                list_data = {}
                async with db.execute("SELECT key, value FROM lists ORDER BY idx ASC") as cursor:
                    async for key, value in cursor:
                        if key not in self.expirations: # Only load non-expiring keys
                            list_data.setdefault(key, []).append(value)
                for key, value_list in list_data.items(): self.store[key] = {"type": "list", "value": value_list}
                
                # Load Hashes
                hash_data = {}
                async with db.execute("SELECT key, field, value FROM hashes") as cursor:
                    async for key, field, value in cursor:
                         if key not in self.expirations:
                            hash_data.setdefault(key, {})[field] = value
                for key, value_dict in hash_data.items(): self.store[key] = {"type": "hash", "value": value_dict}

                # Load Sets
                set_data = {}
                async with db.execute("SELECT key, member FROM sets") as cursor:
                    async for key, member in cursor:
                        if key not in self.expirations:
                            set_data.setdefault(key, set()).add(member)
                for key, value_set in set_data.items(): self.store[key] = {"type": "set", "value": value_set}

                # Load Sorted Sets
                sorted_set_data = {}
                async with db.execute("SELECT key, member, score FROM sorted_sets") as cursor:
                    async for key, member, score in cursor:
                        if key not in self.expirations:
                            sorted_set_data.setdefault(key, []).append((score, member))
                for key, items in sorted_set_data.items():
                    member_map = {m: s for s, m in items}
                    heapq.heapify(items)
                    self.store[key] = {"type": "sorted_set", "value": (items, member_map)}


    async def _snapshot_loop(self):
        while True:
            await asyncio.sleep(self.snapshot_interval)
            async with self.lock:
                data_snapshot = {k: v.copy() for k, v in self.store.items()}
                exp_snapshot = self.expirations.copy()
            try:
                async with aiosqlite.connect(self.db_file) as db:
                    await db.execute("BEGIN TRANSACTION")
                    tables = ["strings", "lists", "hashes", "sets", "sorted_sets"]
                    for table in tables: await db.execute(f"DELETE FROM {table}")
                    
                    string_rows, list_rows, hash_rows, set_rows, sorted_set_rows = [], [], [], [], []
                    for key, data in data_snapshot.items():
                        dtype, value = data["type"], data["value"]
                        expires_at = exp_snapshot.get(key)
                        if dtype == "string": string_rows.append((key, value, expires_at))
                        elif dtype == "list":
                            string_rows.append((key, None, expires_at))
                            list_rows.extend([(key, i, v) for i, v in enumerate(value)])
                        elif dtype == "hash":
                            string_rows.append((key, None, expires_at))
                            hash_rows.extend([(key, f, v) for f, v in value.items()])
                        elif dtype == "set":
                            string_rows.append((key, None, expires_at))
                            set_rows.extend([(key, m) for m in value])
                        elif dtype == "sorted_set":
                            string_rows.append((key, None, expires_at))
                            _, member_map = value
                            sorted_set_rows.extend([(key, m, s) for m, s in member_map.items()])
                    
                    if string_rows: await db.executemany("INSERT OR REPLACE INTO strings (key, value, expires_at) VALUES (?, ?, ?)", string_rows)
                    if list_rows: await db.executemany("INSERT INTO lists (key, idx, value) VALUES (?, ?, ?)", list_rows)
                    if hash_rows: await db.executemany("INSERT INTO hashes (key, field, value) VALUES (?, ?, ?)", hash_rows)
                    if set_rows: await db.executemany("INSERT INTO sets (key, member) VALUES (?, ?)", set_rows)
                    if sorted_set_rows: await db.executemany("INSERT INTO sorted_sets (key, member, score) VALUES (?, ?, ?)", sorted_set_rows)
                    await db.commit()
            except Exception as e:
                pass

    async def _ttl_check_loop(self):
        while True:
            await asyncio.sleep(1)
            now = time.time()
            expired_keys = [key for key, expiry in self.expirations.items() if expiry <= now]
            if expired_keys:
                async with self.lock:
                    for key in expired_keys:
                        if self.expirations.get(key, float('inf')) <= now:
                            await self.trigger_webhook("EXPIRE", key)
                            if self.store.get(key, {}).get("type") == "string":
                                await self.fts_conn.execute("DELETE FROM strings_fts WHERE key = ?", (key,))
                                await self.fts_conn.commit()
                            self.store.pop(key, None)
                            self.expirations.pop(key, None)
                if expired_keys: print(f"[{self.name}] Evicted {len(expired_keys)} expired keys.")

    async def start_background_tasks(self):
        self.snapshot_task = asyncio.create_task(self._snapshot_loop())
        self.ttl_check_task = asyncio.create_task(self._ttl_check_loop())
        self.webhook_worker_task = asyncio.create_task(self._webhook_worker())

    async def update_snapshot_interval(self, new_interval: int):
        self.snapshot_interval = new_interval
        if self.snapshot_task: self.snapshot_task.cancel()
        self.snapshot_task = asyncio.create_task(self._snapshot_loop())
        async with aiosqlite.connect(ADMIN_DB_FILE) as db:
            await db.execute("UPDATE databases SET snapshot_interval = ? WHERE db_name = ?", (new_interval, self.name))
            await db.commit()


class UDFContext:
    def __init__(self, processor: "CommandProcessor"):
        self._processor = processor

    async def get(self, key: str) -> Any: return await self._processor._internal_get(key)
    async def set(self, key: str, value: Any) -> str: return await self._processor._internal_set(key, value)
    async def hgetall(self, key: str) -> Dict: return await self._processor._internal_hgetall(key)
    async def lrange(self, key: str, start: int, stop: int) -> List: return await self._processor._internal_lrange(key, start, stop)


class CommandProcessor:
    def __init__(self, db: DatabaseInstance, permissions: str):
        self.db = db
        self.permissions = permissions
        self.READ_COMMANDS = {
            "GET", "KEYS", "HGET", "HGETALL", "LRANGE", "SMEMBERS", "SINTER", 
            "SUNION", "ZCARD", "ZSCORE", "ZRANGE", "TTL", 
            "PGET", "FT_SEARCH", "JSON_GET", "DUMP" # NEW
        }
        self.WRITE_COMMANDS = {
            "SET", "DEL", "HSET", "INCR", "LPUSH", "LPOP", "RPOP", "SADD",
            "SREM", "ZADD", "ZREM", "EXPIRE", "PSET", "EXEC"
        }
    async def _handle_keys(self, pattern: str = "*"):
        """Returns all key names matching a pattern."""
        async with self.db.lock:
            # First, ensure no keys are expired
            now = time.time()
            expired_keys = [key for key, expiry in self.db.expirations.items() if expiry <= now]
            for key in expired_keys:
                self.db.store.pop(key, None)
                self.db.expirations.pop(key, None)
            
            # Then, find matches
            if pattern == "*":
                return list(self.db.store.keys())
            else:
                return [key for key in self.db.store.keys() if fnmatch.fnmatch(key, pattern)]
    async def execute(self, command_req: CommandRequest):
        command = command_req.command.upper()
        args = command_req.args
        if command in self.READ_COMMANDS:
            if self.permissions not in ["read", "write", "admin"]: raise HTTPException(status_code=403, detail="Insufficient permissions for read command.")
        elif command in self.WRITE_COMMANDS:
            if self.permissions not in ["write", "admin"]: raise HTTPException(status_code=403, detail="Insufficient permissions for write command.")
        else:
            raise HTTPException(status_code=400, detail=f"Command '{command}' not found or supported.")
        
        handler = getattr(self, f"_handle_{command.lower()}", self._not_found)
        return await handler(*args)

    async def _not_found(self, *args):
        raise HTTPException(status_code=500, detail="Internal command handler mapping error.")

    async def _get_key_data(self, key: str, expected_type: Optional[str] = None):
        """Internal helper to get key data, assumes lock may be held."""
        expiry = self.db.expirations.get(key)
        if expiry and expiry <= time.time():
            self.db.store.pop(key, None)
            self.db.expirations.pop(key, None)
            return None
        data = self.db.store.get(key)
        if expected_type and data and data["type"] != expected_type:
            raise HTTPException(status_code=400, detail="WRONGTYPE Operation against a key holding the wrong kind of value.")
        return data


    async def _internal_set(self, key, value):
        str_value = str(value)
        self.db.store[key] = {"type": "string", "value": str_value}
        self.db.expirations.pop(key, None)
        await self.db.fts_conn.execute("INSERT OR REPLACE INTO strings_fts (key, value) VALUES (?, ?)", (key, str_value))
        await self.db.fts_conn.commit()
        await self.db.trigger_webhook("SET", key, value=str_value)
        await pubsub_manager.broadcast(self.db.name, "dashboard-updates", json.dumps({"event": "keychange", "key": key}))
        return "OK"
    async def _handle_dump(self, key: str):
        """Returns detailed information about a key (type, value, TTL)."""
        async with self.db.lock:
            data = await self._get_key_data(key)
            if not data:
                return None
            
            ttl = -1
            expiry = self.db.expirations.get(key)
            if expiry:
                ttl = max(0, int(expiry - time.time()))
                
            value = data["value"]
            # For complex types, convert them to JSON-friendly formats
            if isinstance(value, set):
                value = list(value)
            elif isinstance(value, tuple) and data["type"] == "sorted_set":
                _, member_map = value
                value = dict(sorted(member_map.items(), key=lambda item: item[1]))

            return {
                "key": key,
                "type": data["type"],
                "value": value,
                "ttl": ttl
            }
    async def _internal_get(self, key):
        data = await self._get_key_data(key, "string")
        return data["value"] if data else None

    async def _internal_hgetall(self, key):
        data = await self._get_key_data(key, "hash")
        return data["value"] if data else {}

    async def _internal_lrange(self, key, start, stop):
        data = await self._get_key_data(key, "list")
        if not data: return []
        value = data["value"]
        start, stop = int(start), int(stop)
        return value[start:] if stop == -1 else value[start : stop + 1]


    async def _handle_set(self, key, value):
        async with self.db.lock:
            return await self._internal_set(key, value)

    async def _handle_get(self, key):
        async with self.db.lock:
            return await self._internal_get(key)
            
    async def _handle_hgetall(self, key):
        async with self.db.lock:
            return await self._internal_hgetall(key)
            
    async def _handle_lrange(self, key, start, stop):
        async with self.db.lock:
            return await self._internal_lrange(key, start, stop)

    async def _handle_incr(self, key):
        async with self.db.lock:
            data = await self._get_key_data(key)
            if not data:
                new_value = 1
                await self._internal_set(key, "1")
            else:
                if data["type"] != "string": raise HTTPException(status_code=400, detail="WRONGTYPE")
                try:
                    new_value = int(data["value"]) + 1
                    await self._internal_set(key, str(new_value))
                except ValueError:
                    raise HTTPException(status_code=400, detail="ERR value is not an integer")
            return new_value

    async def _handle_del(self, *keys):
        async with self.db.lock:
            count = 0
            for key in keys:
                if key in self.db.store:
                    await pubsub_manager.broadcast(self.db.name, "dashboard-updates", json.dumps({"event": "keychange", "key": key}))
                    if self.db.store[key]["type"] == "string":
                        await self.db.fts_conn.execute("DELETE FROM strings_fts WHERE key = ?", (key,))
                        await self.db.fts_conn.commit()
                    await self.db.trigger_webhook("DEL", key)
                    del self.db.store[key]
                    self.db.expirations.pop(key, None)
                    count += 1
            return count
        
    async def _handle_exec(self, func_name: str, *args):
        if func_name not in self.db.user_functions:
            raise HTTPException(status_code=404, detail=f"Function '{func_name}' not found.")
        
        udf = self.db.user_functions[func_name]
        context = UDFContext(self)
        
        async with self.db.lock:
            try:
                return await udf(context, *args)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error executing function '{func_name}': {e}")

    async def _handle_pset(self, key, value: Any):
        async with self.db.lock:
            try:
                pickled_obj = pickle.dumps(value)
                b64_encoded = base64.b64encode(pickled_obj).decode('utf-8')
                self.db.store[key] = {"type": "string", "value": b64_encoded}
                self.db.expirations.pop(key, None)
                await self.db.trigger_webhook("SET", key, pickled=True)
                return "OK"
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to pickle object: {e}")

    async def _handle_pget(self, key):
        async with self.db.lock:
            data = await self._get_key_data(key, "string")
            if not data: return None
            try:
                b64_decoded = base64.b64decode(data["value"])
                return pickle.loads(b64_decoded)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to unpickle object: {e}")

    async def _handle_ft_search(self, query: str):
        try:
            cursor = await self.db.fts_conn.execute("SELECT key FROM strings_fts WHERE value MATCH ? ORDER BY rank", (query,))
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"FTS search failed: {e}")

    async def _handle_json_get(self, key: str, path: str):
        async with self.db.lock:
            data = await self._get_key_data(key, "string")
            if not data: return None
            
            try:
                doc = json.loads(data["value"])
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Value is not a valid JSON string.")

            if not path.startswith('$.'):
                raise HTTPException(status_code=400, detail="JSON path must start with '$.'")
            
            parts = path[2:].split('.')
            current = doc
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list):
                    try:
                        idx = int(part)
                        if idx < len(current): current = current[idx]
                        else: return None
                    except ValueError: return None
                else: return None
            return current

    async def _handle_hset(self, key, field, value):
        async with self.db.lock:
            data = await self._get_key_data(key, "hash")
            if not data:
                self.db.store[key] = {"type": "hash", "value": {field: value}}
                return 1
            is_new_field = field not in data["value"]
            data["value"][field] = value
            return 1 if is_new_field else 0
    
    async def _handle_hget(self, key, field):
        async with self.db.lock:
            data = await self._get_key_data(key, "hash")
            return data["value"].get(field) if data else None

    async def _handle_lpush(self, key, *values):
        async with self.db.lock:
            data = await self._get_key_data(key, "list")
            if not data:
                self.db.store[key] = data = {"type": "list", "value": []}
            data["value"] = list(reversed(values)) + data["value"]
            return len(data["value"])
    
    async def _handle_lpop(self, key):
        async with self.db.lock:
            data = await self._get_key_data(key, "list")
            if not data or not data["value"]: return None
            return data["value"].pop(0)

    async def _handle_rpop(self, key):
        async with self.db.lock:
            data = await self._get_key_data(key, "list")
            if not data or not data["value"]: return None
            return data["value"].pop()

    async def _handle_sadd(self, key, *members):
        async with self.db.lock:
            data = await self._get_key_data(key, "set")
            if not data:
                self.db.store[key] = data = {"type": "set", "value": set()}
            initial_len = len(data["value"])
            data["value"].update(members)
            return len(data["value"]) - initial_len

    async def _handle_srem(self, key, *members):
        async with self.db.lock:
            count = 0
            data = await self._get_key_data(key, "set")
            if data:
                for member in members:
                    if member in data["value"]:
                        data["value"].remove(member)
                        count += 1
            return count

    async def _handle_smembers(self, key):
        async with self.db.lock:
            data = await self._get_key_data(key, "set")
            return list(data["value"]) if data else []

    async def _handle_sinter(self, *keys):
        async with self.db.lock:
            if not keys: return []
            sets = []
            for key in keys:
                data = await self._get_key_data(key, "set")
                sets.append(data["value"] if data else set())
            return list(sets[0].intersection(*sets[1:]))

    async def _handle_sunion(self, *keys):
        async with self.db.lock:
            if not keys: return []
            sets = []
            for key in keys:
                data = await self._get_key_data(key, "set")
                sets.append(data["value"] if data else set())
            return list(sets[0].union(*sets[1:]))
        
    async def _handle_zadd(self, key, *args):
        if len(args) % 2 != 0: raise HTTPException(status_code=400, detail="ZADD requires score/member pairs.")
        async with self.db.lock:
            added_count = 0
            data = await self._get_key_data(key, "sorted_set")
            if not data:
                self.db.store[key] = data = {"type": "sorted_set", "value": ([], {})}
            heap, member_map = data["value"]
            for i in range(0, len(args), 2):
                score, member = float(args[i]), args[i+1]
                if member not in member_map: added_count += 1
                member_map[member] = score
            new_heap = [(s, m) for m, s in member_map.items()]
            heapq.heapify(new_heap)
            data["value"] = (new_heap, member_map)
            return added_count

    async def _handle_zrange(self, key, start, stop, withscores=False):
        async with self.db.lock:
            data = await self._get_key_data(key, "sorted_set")
            if not data: return []
            heap, _ = data["value"]
            sorted_items = sorted(heap)
            start, stop = int(start), int(stop)
            
            ranged = sorted_items[start:] if stop == -1 else sorted_items[start : stop + 1]
            
            if str(withscores).upper() == 'WITHSCORES':
                return [item for score, member in ranged for item in (member, score)]
            return [member for score, member in ranged]

    async def _handle_expire(self, key, seconds):
        async with self.db.lock:
            data = await self._get_key_data(key)
            if not data: return 0
            expiry_time = time.time() + int(seconds)
            self.db.expirations[key] = expiry_time
            await self.db.trigger_webhook("EXPIRE_SET", key, expiry_at=expiry_time)
            return 1

    async def _handle_ttl(self, key):
        async with self.db.lock:
            if not await self._get_key_data(key): return -2
            expiry = self.db.expirations.get(key)
            if expiry is None: return -1
            return max(0, int(expiry - time.time()))


# API ENDPOINTS
app = FastAPI(title="AmnesiaDB", description="A Multi-Tenant, Secure, In-Memory Data Store with FastAPI.", version="3.1.0")

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing AmnesiaDB Server...")
    await setup_admin_db()
    await load_keys_from_db()
    
    async with aiosqlite.connect(ADMIN_DB_FILE) as db:
        async with db.execute("SELECT db_name, snapshot_interval FROM databases") as cursor:
            async for row in cursor:
                db_name, interval = row
                instance = DatabaseInstance(name=db_name, snapshot_interval=interval)
                await instance.initialize()
                DATABASES[db_name] = instance
    print("AmnesiaDB Server startup complete.")
    yield
    await HTTP_CLIENT.aclose()
    print("AmnesiaDB Server shutdown.")

app.router.lifespan_context = lifespan

@app.post("/admin/create_database/{db_name}", status_code=201, tags=["Admin"])
async def create_database(db_name: str, config: CreateDbRequest):
    async with GLOBAL_DB_LOCK:
        if db_name in DATABASES: raise HTTPException(status_code=409, detail=f"Database '{db_name}' already exists.")
        
        instance = DatabaseInstance(name=db_name, snapshot_interval=config.snapshot_interval)
        await instance.initialize()
        DATABASES[db_name] = instance
        
        async with aiosqlite.connect(ADMIN_DB_FILE) as db:
            await db.execute("INSERT INTO databases (db_name, snapshot_interval) VALUES (?, ?)", (db_name, config.snapshot_interval))
            admin_key = generate_api_key()
            await db.execute("INSERT INTO api_keys (api_key, db_name, permissions) VALUES (?, ?, ?)", (admin_key, db_name, "admin"))
            await db.commit()
        
        API_KEYS[admin_key] = {"db_name": db_name, "permissions": "admin"}
        return { "message": "Database created successfully.", "db_name": db_name, "admin_api_key": admin_key }

@app.post("/{db_name}/command", tags=["Data Commands"])
async def execute_command(request: CommandRequest, auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, permissions = auth
    processor = CommandProcessor(db_instance, permissions)
    result = await processor.execute(request)
    return {"result": result}
    
@app.post("/{db_name}/publish/{channel}", tags=["Pub/Sub"])
async def publish(channel: str, request: PublishRequest, auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, permissions = auth
    if permissions not in ["write", "admin"]: raise HTTPException(status_code=403, detail="Insufficient permissions to publish.")
    await pubsub_manager.broadcast(db_instance.name, channel, request.message)
    return {"status": "message published"}

@app.websocket("/{db_name}/ws/subscribe/{channel}")
async def subscribe(websocket: WebSocket, channel: str, db_instance: DatabaseInstance = Depends(get_db_for_ws)):
    await pubsub_manager.connect(db_instance.name, channel, websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        pubsub_manager.disconnect(db_instance.name, channel, websocket)

@app.post("/{db_name}/admin/create_key", tags=["Admin"])
async def create_api_key(request: CreateKeyRequest, auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, permissions = auth
    if permissions != "admin": raise HTTPException(status_code=403, detail="Only admin keys can create new keys.")
    
    new_key = generate_api_key()
    async with aiosqlite.connect(ADMIN_DB_FILE) as db:
        await db.execute("INSERT INTO api_keys (api_key, db_name, permissions) VALUES (?, ?, ?)", (new_key, db_instance.name, request.permissions))
        await db.commit()
    
    API_KEYS[new_key] = {"db_name": db_instance.name, "permissions": request.permissions}
    return {"api_key": new_key, "permissions": request.permissions}

@app.put("/{db_name}/admin/config", tags=["Admin"])
async def update_db_config(request: UpdateConfigRequest, auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, permissions = auth
    if permissions != "admin": raise HTTPException(status_code=403, detail="Only admin keys can update config.")
    await db_instance.update_snapshot_interval(request.snapshot_interval)
    return {"message": f"Snapshot interval for '{db_instance.name}' updated to {request.snapshot_interval}s."}

@app.post("/{db_name}/admin/webhooks", status_code=201, tags=["Admin - Webhooks"])
async def create_webhook(request: WebhookRequest, auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, permissions = auth
    if permissions != "admin": raise HTTPException(status_code=403, detail="Admin permissions required.")
    async with aiosqlite.connect(db_instance.db_file) as db:
        cursor = await db.execute("INSERT INTO webhooks (key_pattern, url) VALUES (?, ?)", (request.key_pattern, request.url))
        await db.commit()
        hook_id = cursor.lastrowid
        db_instance.webhooks[hook_id] = {"key_pattern": request.key_pattern, "url": request.url}
    return {"message": "Webhook created", "id": hook_id}

@app.get("/{db_name}/admin/webhooks", tags=["Admin - Webhooks"])
async def list_webhooks(auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, permissions = auth
    if permissions != "admin": raise HTTPException(status_code=403, detail="Admin permissions required.")
    return db_instance.webhooks

@app.post("/{db_name}/admin/functions/{func_name}", tags=["Admin - UDFs"])
async def upload_function(func_name: str, request: FunctionUploadRequest, auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, permissions = auth
    if permissions != "admin": raise HTTPException(status_code=403, detail="Admin permissions required.")
    
    try:
        code = textwrap.dedent(request.code)
        local_scope = {}
        exec(code, {}, local_scope)
        if func_name not in local_scope or not asyncio.iscoroutinefunction(local_scope[func_name]):
            raise ValueError(f"Code must define an async function named '{func_name}'.")
        db_instance.user_functions[func_name] = local_scope[func_name]
        return {"message": f"Function '{func_name}' uploaded successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to upload function: {e}")

@app.get("/{db_name}/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def get_dashboard(request: Request, db_name: str):
    return templates.TemplateResponse("dashboard.html", {"request": request, "db_name": db_name})

@app.get("/{db_name}/dashboard/api/stats", response_class=JSONResponse, tags=["Dashboard"])
async def get_dashboard_stats(auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, _ = auth
    async with db_instance.lock:
        return {
            "db_name": db_instance.name,
            "key_count": len(db_instance.store),
            "expiration_count": len(db_instance.expirations),
            "snapshot_interval": db_instance.snapshot_interval
        }
        
@app.get("/{db_name}/dashboard/api/keys", response_class=JSONResponse, tags=["Dashboard"])
async def get_dashboard_keys(auth: Tuple[DatabaseInstance, str] = Depends(get_db_and_auth)):
    db_instance, _ = auth
    async with db_instance.lock:
        return {"keys": list(db_instance.store.keys())}

# --- 7. Main Execution ---
def setup_dashboard_template():
    if not os.path.exists("templates"):
        os.makedirs("templates")
    with open("templates/dashboard.html", "w") as f:
        f.write("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AmnesiaDB Dashboard | {{ db_name }}</title>
    <style>
        :root { --blue: #0d6efd; --gray: #6c757d; --light-gray: #f8f9fa; --border-color: #dee2e6; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--light-gray); color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        header { background: var(--blue); color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { margin: 0; font-size: 24px; }
        #ws-status { font-size: 14px; background: rgba(255,255,255,0.2); padding: 5px 10px; border-radius: 5px; }
        .content { display: flex; }
        .sidebar { width: 350px; border-right: 1px solid var(--border-color); padding: 20px; }
        .main { flex-grow: 1; padding: 20px; }
        h2 { border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-top: 0; }
        .api-key-section, .stats-section { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid var(--border-color); border-radius: 4px; }
        button { background: var(--blue); color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
        .stat { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
        #key-list { list-style-type: none; padding: 0; margin-top: 10px; max-height: 50vh; overflow-y: auto; }
        #key-list li { padding: 8px; cursor: pointer; border-radius: 4px; }
        #key-list li:hover, #key-list li.active { background-color: #e9ecef; }
        #key-value-display { background: #2d333b; color: #cdd9e5; padding: 15px; border-radius: 6px; white-space: pre-wrap; word-break: break-all; min-height: 200px; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AmnesiaDB Dashboard</h1>
            <span id="ws-status"> Disconnected</span>
        </header>
        
        <div class="content">
            <div class="sidebar">
                <div class="api-key-section">
                    <h2>Connection</h2>
                    <input type="password" id="api-key-input" placeholder="Enter Admin or Read API Key">
                    <button id="connect-btn" style="margin-top: 10px;">Connect</button>
                </div>
                
                <div id="data-browser" class="hidden">
                    <h2>Key Browser</h2>
                    <input type="text" id="key-filter-input" placeholder="Filter keys...">
                    <ul id="key-list"></ul>
                </div>
            </div>
            
            <div class="main">
                <div id="main-content" class="hidden">
                    <h2>Server Stats</h2>
                    <div class="stats-section">
                        <div class="stat"><span>Database Name:</span> <strong id="stat-db-name">{{ db_name }}</strong></div>
                        <div class="stat"><span>Total Keys:</span> <strong id="stat-key-count">N/A</strong></div>
                        <div class="stat"><span>Keys with TTL:</span> <strong id="stat-expiration-count">N/A</strong></div>
                        <div class="stat"><span>Snapshot Interval:</span> <strong id="stat-snapshot-interval">N/A</strong></div>
                    </div>

                    <h2>Key Inspector</h2>
                    <div id="key-value-display">Select a key to view its value.</div>
                </div>
                 <div id="welcome-message">
                    <h2>Welcome!</h2>
                    <p>Please enter a valid API key in the sidebar to connect to the <strong>{{ db_name }}</strong> database and view its data.</p>
                </div>
            </div>
        </div>
    </div>

<script>
    const DB_NAME = '{{ db_name }}';
    let apiKey = '';
    let allKeys = [];

    const apiKeyInput = document.getElementById('api-key-input');
    const connectBtn = document.getElementById('connect-btn');
    const keyFilterInput = document.getElementById('key-filter-input');
    const keyList = document.getElementById('key-list');
    const keyValueDisplay = document.getElementById('key-value-display');
    const wsStatus = document.getElementById('ws-status');
    
    // UI Panels
    const dataBrowser = document.getElementById('data-browser');
    const mainContent = document.getElementById('main-content');
    const welcomeMessage = document.getElementById('welcome-message');

    // --- API Functions ---
    async function apiCommand(command, args = []) {
        if (!apiKey) {
            alert('API Key is not set.');
            return;
        }
        const response = await fetch(`/${DB_NAME}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-KEY': apiKey },
            body: JSON.stringify({ command, args })
        });
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'API request failed');
        }
        const data = await response.json();
        return data.result;
    }
    
    async function getStats() {
        if (!apiKey) return;
        const response = await fetch(`/${DB_NAME}/dashboard/api/stats`, {
            headers: { 'X-API-KEY': apiKey }
        });
        if (!response.ok) return;
        const stats = await response.json();
        document.getElementById('stat-key-count').textContent = stats.key_count;
        document.getElementById('stat-expiration-count').textContent = stats.expiration_count;
        document.getElementById('stat-snapshot-interval').textContent = `${stats.snapshot_interval}s`;
    }

    // --- DOM & Update Functions ---
    function renderKeys(filter = '') {
        keyList.innerHTML = '';
        const filteredKeys = allKeys.filter(key => key.includes(filter));
        filteredKeys.forEach(key => {
            const li = document.createElement('li');
            li.textContent = key;
            li.onclick = () => showKeyValue(key);
            keyList.appendChild(li);
        });
    }
    
    async function showKeyValue(key) {
        // Highlight active key
        document.querySelectorAll('#key-list li').forEach(li => {
            li.classList.toggle('active', li.textContent === key);
        });
        
        try {
            keyValueDisplay.textContent = 'Loading...';
            const data = await apiCommand('DUMP', [key]);
            if (data) {
                const prettyValue = JSON.stringify(data.value, null, 2);
                keyValueDisplay.textContent = `// type: ${data.type} | ttl: ${data.ttl}s\\n\\n${prettyValue}`;
            } else {
                keyValueDisplay.textContent = `// Key not found or expired.`;
            }
        } catch (error) {
            keyValueDisplay.textContent = `Error fetching key: ${error.message}`;
        }
    }
    
    async function refreshData() {
        try {
            allKeys = await apiCommand('KEYS', ['*']); // Assuming a KEYS command exists
            allKeys.sort();
            await getStats();
            renderKeys(keyFilterInput.value);
        } catch (error) {
            console.error('Failed to refresh data:', error);
            alert(`Connection failed: ${error.message}. Please check your API key.`);
            disconnect();
        }
    }

    // --- WebSocket ---
    function connectWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/${DB_NAME}/ws/subscribe/dashboard-updates?token=${encodeURIComponent(apiKey)}`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('WebSocket connected.');
            wsStatus.textContent = 'Connected (Live)';
        };

        ws.onmessage = (event) => {
            console.log('Received update:', event.data);
            refreshData(); // Refresh data on any change
        };

        ws.onclose = () => {
            console.log('WebSocket disconnected.');
            wsStatus.textContent = 'Disconnected';
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            wsStatus.textContent = 'Error';
        }
    }

    function showDashboard() {
        welcomeMessage.classList.add('hidden');
        dataBrowser.classList.remove('hidden');
        mainContent.classList.remove('hidden');
    }

    function disconnect() {
        apiKey = '';
        apiKeyInput.value = '';
        welcomeMessage.classList.remove('hidden');
        dataBrowser.classList.add('hidden');
        mainContent.classList.add('hidden');
    }
    
    // --- Event Listeners ---
    connectBtn.onclick = async () => {
        apiKey = apiKeyInput.value.trim();
        if (!apiKey) {
            alert('Please enter an API Key.');
            return;
        }
        showDashboard();
        await refreshData();
        connectWebSocket();
    };

    keyFilterInput.onkeyup = () => {
        renderKeys(keyFilterInput.value);
    };
</script>
</body>
</html>
""")

@app.get("/", response_class=HTMLResponse, tags=["Home"])
async def home(request: Request):
    return """
<!DOCTYPE html>\n<html lang="en">\n<head>\n <meta charset="UTF-8" />\n <meta name="viewport" content="width=device-width, initial-scale=1.0"/>\n <title>AmnesiaDB</title>\n <style>\n body {\n margin: 0;\n padding: 0;\n font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;\n background: linear-gradient(to right, #0f2027, #203a43, #2c5364);\n color: #fff;\n display: flex;\n flex-direction: column;\n justify-content: center;\n align-items: center;\n min-height: 100vh;\n text-align: center;\n }\n h1 {\n font-size: 3rem;\n margin-bottom: 0.5rem;\n color: #00ffd0;\n }\n h2 {\n font-weight: 300;\n font-size: 1.5rem;\n margin-top: 0;\n color: #f0f0f0;\n }\n a {\n color: #1abc9c;\n text-decoration: none;\n font-weight: bold;\n }\n a:hover {\n text-decoration: underline;\n }\n .footer {\n margin-top: 2rem;\n font-size: 0.9rem;\n opacity: 0.8;\n }\n .comparison {\n max-width: 900px;\n text-align: left;\n margin-top: 3rem;\n background: rgba(255,255,255,0.05);\n padding: 2rem;\n border-radius: 1rem;\n box-shadow: 0 4px 15px rgba(0,0,0,0.3);\n }\n .comparison h2 {\n color: #00ffd0;\n font-size: 2rem;\n margin-bottom: 1rem;\n }\n .comparison h3 {\n margin-top: 1.5rem;\n color: #1abc9c;\n }\n .comparison p {\n margin: 0.5rem 0;\n line-height: 1.6;\n }\n .comparison ul {\n margin: 0.5rem 0 1rem 1.5rem;\n line-height: 1.6;\n }\n </style>\n</head>\n<body>\n <h1>AmnesiaDB</h1>\n <h2>A Multi-Tenant, Secure, In-Memory Data Store</h2>\n <h2>Now with Webhooks, Dashboard, Python-native features, and Advanced Querying</h2>\n <p>\n For documentation, visit <a href="/docs">/docs</a>\n </p>\n\n <div class="comparison">\n <h2>AmnesiaDB vs Redis</h2>\n\n <h3>✅ Similarities</h3>\n <p>AmnesiaDB includes all Redis data structures and commands, so developers familiar with Redis can use it seamlessly.</p>\n\n <h3>🚀 Differences</h3>\n\n <h4>1. 🕸️ Web-Native Features (Leveraging FastAPI)</h4>\n <ul>\n <li><strong>Protocol:</strong> Redis speaks its own protocol. AmnesiaDB speaks HTTP, enabling native web integrations.</li>\n <li><strong>Webhooks on Key Events:</strong> Configure AmnesiaDB to POST to your API when a key changes, deletes, or expires. This is simpler and more direct than Redis Keyspace Notifications.</li>\n <li><strong>Built-in Dashboard:</strong> AmnesiaDB ships with a secure web interface for monitoring stats and browsing keys. Redis requires external tools like RedisInsight.</li>\n </ul>\n\n <h4>2. 🐍 Python-Native Superpowers</h4>\n <ul>\n <li><strong>Automatic Python Object Serialization:</strong> Store and retrieve Python objects directly without manual serialization.</li>\n <li><strong>Server-Side Python Functions (UDFs):</strong> Upload and execute Python functions atomically on the server, unlocking the entire Python ecosystem (NumPy, Pandas, etc.).</li>\n </ul>\n\n <h4>3. 🗃️ Advanced Data Querying (Leveraging SQLite)</h4>\n <ul>\n <li><strong>Full-Text Search:</strong> Use SQLite’s FTS5 extension for powerful text search without external modules.</li>\n <li><strong>Direct JSON Querying:</strong> Query structured JSON values directly with SQLite JSON functions.</li>\n </ul>\n </div>\n\n <div class="footer">\n Author: <a href="https://www.linkedin.com/in/gupta-ojas\
" target="_blank">Ojas Gupta</a>\n </div>\n</body>\n</html>
    """


import logging
logging.getLogger("uvicorn").disabled = True
logging.getLogger("uvicorn.error").disabled = True
logging.getLogger("uvicorn.access").disabled = True
logging.getLogger("fastapi").disabled = True
from pyfiglet import Figlet

def print_banner():
    try:
        f = Figlet(font='standard')  # Try 'standard', 'slant', 'big', 'block', etc.
        print(f.renderText('AMNESIADB'))
    except:
        print("AmnesiaDB")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the AmnesiaDB server.")
    parser.add_argument(
        "--host", 
        type=str, 
        default="127.0.0.1", 
        help="Host address to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=2707, 
        help="Port number to bind to (default: 2707)"
    )
    print_banner()
    args = parser.parse_args()
    setup_dashboard_template()
    print("Version v3.1.0")
    print(f"AmnesiaDB server running at http://{args.host}:{args.port}/")

    print("*"*80)
    print("To update: kindly check https://xplainnn.com")
    uvicorn.run(app, host=args.host, port=args.port,log_level="critical", access_log=False)
