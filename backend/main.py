import base64
import os
import time
import hashlib
import secrets
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ecdsa import VerifyingKey, NIST256p, BadSignatureError

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# In-memory storage (swap for a real database in production)
# We only ever store PUBLIC keys and ciphertext. Passwords, private
# keys, and plaintext message content never reach this server.
# ============================================================
users = {}           # username -> {"authPublicKey": str, "encryptionPublicKey": str}
challenges = {}      # username -> {"value": str, "expires": timestamp}
sessions = {}        # session_token -> {"username": str, "expires": timestamp}
transfer_chain = []  # append-only hash-chained log of generic data transfers (hash only)
message_chain = []   # append-only hash-chained log of E2E encrypted chat messages (stores ciphertext)

CHALLENGE_TTL_SECONDS = 60
SESSION_TTL_SECONDS = 3600  # 1 hour
GENESIS_HASH = "0" * 64


class RegisterRequest(BaseModel):
    username: str
    authPublicKey: str        # base64, raw ECDSA P-256 public key — used only to verify login signatures
    encryptionPublicKey: str  # base64, raw ECDH P-256 public key — used only for E2E key agreement


class LoginVerifyRequest(BaseModel):
    username: str
    signature: str  # base64-encoded ECDSA signature over the challenge string


class TransferRequest(BaseModel):
    recipient: str
    payload: str  # base64-encoded data. Encrypt this client-side first if confidentiality is required.


class SendMessageRequest(BaseModel):
    recipient: str
    ciphertext: str  # base64 AES-GCM ciphertext, encrypted client-side
    iv: str           # base64 AES-GCM initialization vector, generated client-side


# ============================================================
# Registration / login (passkey-style challenge-response)
# ============================================================
@app.post("/api/register")
def register(data: RegisterRequest):
    if data.username in users:
        raise HTTPException(status_code=409, detail="Username already taken.")
    users[data.username] = {
        "authPublicKey": data.authPublicKey,
        "encryptionPublicKey": data.encryptionPublicKey,
    }
    return {"success": True, "message": "Account created."}


@app.get("/api/challenge")
def get_challenge(username: str):
    if username not in users:
        raise HTTPException(status_code=404, detail="No account with this username.")
    challenge_value = base64.b64encode(os.urandom(32)).decode()
    challenges[username] = {"value": challenge_value, "expires": time.time() + CHALLENGE_TTL_SECONDS}
    return {"challenge": challenge_value}


@app.post("/api/login-verify")
def login_verify(data: LoginVerifyRequest):
    record = challenges.get(data.username)
    if not record or time.time() > record["expires"]:
        raise HTTPException(status_code=400, detail="Challenge expired. Request a new one.")

    user = users.get(data.username)
    if not user:
        raise HTTPException(status_code=404, detail="No account with this username.")

    try:
        raw_point = base64.b64decode(user["authPublicKey"])
        # Web Crypto exports uncompressed EC points as 0x04 || X || Y (65 bytes for P-256)
        x_y_bytes = raw_point[1:]  # strip the 0x04 prefix
        vk = VerifyingKey.from_string(x_y_bytes, curve=NIST256p)

        signature_bytes = base64.b64decode(data.signature)
        challenge_bytes = record["value"].encode()

        vk.verify(signature_bytes, challenge_bytes, hashfunc=hashlib.sha256)
    except (BadSignatureError, ValueError, Exception):
        raise HTTPException(status_code=401, detail="Signature verification failed.")

    del challenges[data.username]  # one-time use

    session_token = secrets.token_urlsafe(32)
    sessions[session_token] = {"username": data.username, "expires": time.time() + SESSION_TTL_SECONDS}

    return {"success": True, "message": "Login successful.", "sessionToken": session_token}


# ============================================================
# Session auth dependency
# ============================================================
def get_current_user(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    token = authorization.removeprefix("Bearer ")
    record = sessions.get(token)
    if not record or time.time() > record["expires"]:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    return record["username"]


# ============================================================
# Encryption key directory
# Lets any logged-in user look up any other user's ECDH public key
# to start an E2E encrypted chat with them.
# ============================================================
@app.get("/api/users/{username}/key")
def get_encryption_key(username: str, requester: str = Depends(get_current_user)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="No account with this username.")
    return {"username": username, "encryptionPublicKey": user["encryptionPublicKey"]}


# ============================================================
# Shared hash-chain helper
# Each block links to the previous block's hash, so editing any past
# block breaks every hash after it — tamper-evident without needing
# a distributed blockchain network.
# ============================================================
def _chain_hash(index, timestamp, sender, recipient, content_hash, previous_hash) -> str:
    block_string = f"{index}|{timestamp}|{sender}|{recipient}|{content_hash}|{previous_hash}"
    return hashlib.sha256(block_string.encode()).hexdigest()


# ============================================================
# Generic tamper-evident transfer log (hash only, no content stored)
# ============================================================
@app.post("/api/transfer")
def transfer_data(data: TransferRequest, username: str = Depends(get_current_user)):
    if data.recipient not in users:
        raise HTTPException(status_code=404, detail="Recipient does not exist.")

    try:
        payload_bytes = base64.b64decode(data.payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Payload must be valid base64.")

    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    index = len(transfer_chain)
    timestamp = time.time()
    previous_hash = transfer_chain[-1]["block_hash"] if transfer_chain else GENESIS_HASH
    block_hash = _chain_hash(index, timestamp, username, data.recipient, payload_hash, previous_hash)

    block = {
        "index": index, "timestamp": timestamp, "sender": username, "recipient": data.recipient,
        "payload_hash": payload_hash, "previous_hash": previous_hash, "block_hash": block_hash,
    }
    transfer_chain.append(block)
    return {"success": True, "block": block}


@app.get("/api/chain/verify")
def verify_transfer_chain(username: str = Depends(get_current_user)):
    return _verify_generic_chain(transfer_chain)


# ============================================================
# E2E encrypted chat
# Ciphertext + iv are opaque to this server — only sender and
# recipient can derive the AES key (via ECDH) needed to read them.
# ============================================================
@app.post("/api/messages")
def send_message(data: SendMessageRequest, username: str = Depends(get_current_user)):
    if data.recipient not in users:
        raise HTTPException(status_code=404, detail="Recipient does not exist.")

    try:
        ciphertext_bytes = base64.b64decode(data.ciphertext)
        base64.b64decode(data.iv)  # validate it's well-formed base64
    except Exception:
        raise HTTPException(status_code=400, detail="ciphertext and iv must be valid base64.")

    content_hash = hashlib.sha256(ciphertext_bytes).hexdigest()
    index = len(message_chain)
    timestamp = time.time()
    previous_hash = message_chain[-1]["block_hash"] if message_chain else GENESIS_HASH
    block_hash = _chain_hash(index, timestamp, username, data.recipient, content_hash, previous_hash)

    block = {
        "index": index, "timestamp": timestamp, "sender": username, "recipient": data.recipient,
        "ciphertext": data.ciphertext, "iv": data.iv,
        "previous_hash": previous_hash, "block_hash": block_hash,
    }
    message_chain.append(block)
    return {"success": True, "message": block}


@app.get("/api/messages/{other_username}")
def get_conversation(other_username: str, username: str = Depends(get_current_user)):
    convo = [
        m for m in message_chain
        if (m["sender"] == username and m["recipient"] == other_username)
        or (m["sender"] == other_username and m["recipient"] == username)
    ]
    return {"messages": convo}


@app.get("/api/conversations")
def list_conversations(username: str = Depends(get_current_user)):
    partners = set()
    for m in message_chain:
        if m["sender"] == username:
            partners.add(m["recipient"])
        elif m["recipient"] == username:
            partners.add(m["sender"])
    return {"conversations": sorted(partners)}


@app.get("/api/messages/verify")
def verify_message_chain(username: str = Depends(get_current_user)):
    return _verify_generic_chain(message_chain)


def _verify_generic_chain(chain):
    previous_hash = GENESIS_HASH
    for block in chain:
        content_hash = block.get("payload_hash") or hashlib.sha256(
            base64.b64decode(block["ciphertext"])
        ).hexdigest()
        expected_hash = _chain_hash(
            block["index"], block["timestamp"], block["sender"],
            block["recipient"], content_hash, previous_hash
        )
        if block["previous_hash"] != previous_hash or block["block_hash"] != expected_hash:
            return {"valid": False, "brokenAtIndex": block["index"]}
        previous_hash = block["block_hash"]
    return {"valid": True, "blocks": len(chain)}


@app.get("/")
def root():
    return {
        "status": "Fortress backend running",
        "users_registered": len(users),
        "transfer_blocks": len(transfer_chain),
        "message_blocks": len(message_chain),
    }