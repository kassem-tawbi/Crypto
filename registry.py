# registry.py
# MongoDB-backed registry for hospitals (name, host, port, sign & enc public keys).

import logging
from typing import Optional, Dict, Any, List

from pymongo import MongoClient, errors
import certifi

# -------------------------------------------------------------------
# 1) CONFIGURE THIS WITH YOUR REAL ATLAS CONNECTION STRING
#    (Keep the "mongodb+srv://" prefix)
# -------------------------------------------------------------------
MONGO_URI = (
    "mongodb+srv://trkhmz503_db_user:root@p2pfilesharing.l5vvizb.mongodb.net/?appName=p2pFileSharing"
)

DB_NAME = "cryptop2p"
COLLECTION_NAME = "hospitals"

logger = logging.getLogger("registry")

# -------------------------------------------------------------------
# 2) CREATE A GLOBAL CLIENT WITH PROPER TLS SETTINGS
# -------------------------------------------------------------------
try:
    _client = MongoClient(
        MONGO_URI,
        # Atlas requires TLS; this ensures we use a modern CA bundle
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=30_000,  # 30 seconds
    )
    _db = _client[DB_NAME]
    _coll = _db[COLLECTION_NAME]
except Exception as e:
    # If this fails, calls to register/get will still raise, but at least we log why.
    logger.exception("Failed to create MongoDB client: %s", e)
    _client = None
    _db = None
    _coll = None


# -------------------------------------------------------------------
# 3) PUBLIC API
# -------------------------------------------------------------------

def register_hospital(
    name: str,
    p2p_host: str,
    p2p_port: int,
    sign_pub_pem: str,
    enc_pub_pem: str,
) -> None:
    """
    Upsert hospital entry:
      - name: hospital identifier (e.g., "Hospital_A")
      - p2p_host: external/public host/IP
      - p2p_port: external/public port
      - sign_pub_pem: PEM string of RSA signing public key
      - enc_pub_pem: PEM string of RSA encryption public key
    """
    if _coll is None:
        raise RuntimeError("MongoDB client is not initialized (see earlier errors).")

    doc = {
        "name": name,
        "p2p_host": p2p_host,
        "p2p_port": int(p2p_port),
        "sign_pub_key": sign_pub_pem,
        "enc_pub_key": enc_pub_pem,
    }

    try:
        _coll.update_one({"name": name}, {"$set": doc}, upsert=True)
        logger.info("Registry upsert for %s succeeded.", name)
    except errors.PyMongoError as e:
        logger.exception("register_hospital failed for %s: %s", name, e)
        raise


def get_hospital(name: str) -> Optional[Dict[str, Any]]:
    """
    Look up hospital by name. Returns e.g.:

    {
        "name": "Hospital_B",
        "p2p_host": "203.0.113.10",
        "p2p_port": 65002,
        "sign_pub_key": "-----BEGIN PUBLIC KEY----- ...",
        "enc_pub_key": "-----BEGIN PUBLIC KEY----- ...",
    }
    or None if not found.
    """
    if _coll is None:
        raise RuntimeError("MongoDB client is not initialized (see earlier errors).")

    try:
        doc = _coll.find_one({"name": name})
    except errors.PyMongoError as e:
        logger.exception("get_hospital failed for %s: %s", name, e)
        raise

    if not doc:
        return None

    return {
        "name": doc.get("name"),
        "p2p_host": doc.get("p2p_host"),
        "p2p_port": doc.get("p2p_port"),
        "sign_pub_key": doc.get("sign_pub_key"),
        "enc_pub_key": doc.get("enc_pub_key"),
    }


def list_hospitals(exclude_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Return all hospitals registered in the registry.

    Each entry has keys:
      - name, p2p_host, p2p_port, sign_pub_key, enc_pub_key
    """
    if _coll is None:
        raise RuntimeError("MongoDB client is not initialized (see earlier errors).")

    query: Dict[str, Any] = {}
    if exclude_name is not None:
        query["name"] = {"$ne": exclude_name}

    try:
        cursor = _coll.find(query)
    except errors.PyMongoError as e:
        logger.exception("list_hospitals failed: %s", e)
        raise

    result: List[Dict[str, Any]] = []
    for doc in cursor:
        result.append(
            {
                "name": doc.get("name"),
                "p2p_host": doc.get("p2p_host"),
                "p2p_port": doc.get("p2p_port"),
                "sign_pub_key": doc.get("sign_pub_key"),
                "enc_pub_key": doc.get("enc_pub_key"),
            }
        )
    return result
