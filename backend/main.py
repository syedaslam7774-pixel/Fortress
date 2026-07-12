import base64
import os
import time
import hashlib
from fastapi import FastAPI, HTTPException
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

# --- In-memory storage (swap for a real database in production) ---
# We only ever store the PUBLIC key. Passwords and private keys never reach this server.
users = {}          # username -> public key bytes
challenges = {}     # username -> {"value": str, "expires": timestamp}

CHALLENGE_TTL_SECONDS = 60


class RegisterRequest(BaseModel):
    username: str
    publicKey: str  # base64-encoded raw EC public key (from crypto.subtle.exportKey("raw", ...))


class LoginVerifyRequest(BaseModel):
    username: str
    signature: str  # base64-encoded ECDSA signature over the challenge string


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
    return {"success": True, "message": "Login successful."}


@app.get("/")
def root():
    return {"status": "Fortress backend running", "users_registered": len(users)}