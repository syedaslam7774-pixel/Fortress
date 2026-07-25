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
# We only ever store the PUBLIC key. Passwords and private keys never reach this server.
# ============================================================
users = {}           # username -> public key bytes
challenges = {}      # username -> {"value": str, "expires": timestamp}
sessions = {}        # session_token -> {"username": str, "expires": timestamp}
transfer_chain = []  # append-only list of hash-chained transfer blocks

CHALLENGE_TTL_SECONDS = 60
SESSION_TTL_SECONDS = 3600  # 1 hour
GENESIS_HASH = "0" * 64


class RegisterRequest(BaseModel):
    username: str
    publicKey: str  # base64-encoded raw EC public key (from crypto.subtle.exportKey("raw", ...))


class LoginVerifyRequest(BaseModel):
    username: str
    signature: str  # base64-encoded ECDSA signature over the challenge string


class TransferRequest(BaseModel):
    recipient: str
    payload: str  # base64-encoded data. Encrypt this client-side first if confidentiality is required.


# ============================================================
# Registration / login (passkey-style challenge-response)
# ============================================================
@app.post("/api/register")
def register(data: RegisterRequest):
    if data.username in users:
        raise HTTPException(status_code=409, detail="Username already taken.")
    users[data.username] = data.publicKey
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

    public_key_b64 = users.get(data.username)
    if not public_key_b64:
        raise HTTPException(status_code=404, detail="No account with this username.")

    try:
        raw_point = base64.b64decode(public_key_b64)
        # Web Crypto exports uncompressed EC points as 0x04 || X || Y (65 bytes for P-256)
        x_y_bytes = raw_point[1:]  # strip the 0x04 prefix
        vk = VerifyingKey.from_string(x_y_bytes, curve=NIST256p)

        signature_bytes = base64.b64decode(data.signature)
        challenge_bytes = record["value"].encode()

        vk.verify(signature_bytes, challenge_bytes, hashfunc=hashlib.sha256)
    except (BadSignatureError, ValueError, Exception):
        raise HTTPException(status_code=401, detail="Signature verification failed.")

    del challenges[data.username]  # one-time use

    # Issue a session token so the client can prove "logged in" on later requests.
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
# Hash-chained transfer log
# Each block links to the previous block's hash, so editing any past
# block breaks every hash after it — the log becomes tamper-evident
# without needing a distributed blockchain network.
# We store only a hash of the payload, never the payload itself, so
# the log doesn't become a second copy of sensitive data.
# ============================================================
def _chain_hash(index, timestamp, sender, recipient, payload_hash, previous_hash) -> str:
    block_string = f"{index}|{timestamp}|{sender}|{recipient}|{payload_hash}|{previous_hash}"
    return hashlib.sha256(block_string.encode()).hexdigest()


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
        "index": index,
        "timestamp": timestamp,
        "sender": username,
        "recipient": data.recipient,
        "payload_hash": payload_hash,
        "previous_hash": previous_hash,
        "block_hash": block_hash,
    }
    transfer_chain.append(block)

    return {"success": True, "block": block}


@app.get("/api/chain")
def get_chain(username: str = Depends(get_current_user)):
    return {"chain": transfer_chain, "length": len(transfer_chain)}


@app.get("/api/chain/verify")
def verify_chain(username: str = Depends(get_current_user)):
    previous_hash = GENESIS_HASH
    for block in transfer_chain:
        expected_hash = _chain_hash(
            block["index"], block["timestamp"], block["sender"],
            block["recipient"], block["payload_hash"], previous_hash
        )
        if block["previous_hash"] != previous_hash or block["block_hash"] != expected_hash:
            return {"valid": False, "brokenAtIndex": block["index"]}
        previous_hash = block["block_hash"]
    return {"valid": True, "blocks": len(transfer_chain)}


@app.get("/")
def root():
    return {
        "status": "Fortress backend running",
        "users_registered": len(users),
        "transfer_blocks": len(transfer_chain),
    }