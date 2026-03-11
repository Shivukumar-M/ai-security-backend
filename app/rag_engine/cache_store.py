# backend/app/rag_engine/cache_store.py

import json
import os
import time
import hashlib

CACHE_FILE = "rag_cache.json"
CACHE_TTL = 86400  # 24 hours


class RAGCache:
    def __init__(self):
        self.cache = {}
        self._load()

    def _hash(self, data: dict) -> str:
        clean = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(clean).hexdigest()

    def _load(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    self.cache = json.load(f)
            except:
                self.cache = {}

    def _save(self):
        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f)

    def get(self, data: dict):
        key = self._hash(data)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry["timestamp"] < CACHE_TTL:
                return entry["value"]
        return None

    def set(self, data: dict, value: dict):
        key = self._hash(data)
        self.cache[key] = {
            "value": value,
            "timestamp": time.time()
        }
        self._save()


cache_store = RAGCache()
