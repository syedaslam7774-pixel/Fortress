import base64
import os
import time
import hashlib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from supabase import create_client, Client  # type: ignore

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://fortress-zeta-eight.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Supabase connection ---
# Set these two as Environment Variables in Vercel (never hardcode them in code).
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Challenges can safely stay in memory — they're short-lived (60s) and
# losing one on a rare cold start just means the user clicks login again.
challenges = {}
CHALLENGE_TTL_SECONDS = 60


class RegisterRequest(BaseModel):
    username: str
    publicKey: str


class LoginVerifyRequest(BaseModel):
    username: str
    signature: str


@app.post("/api/register")
def register(data: RegisterRequest):
    existing = supabase.table("users").select("username").eq("username", data.username).execute()
    if existing.data:
        raise HTTPException(status_code=409, detail="Username already taken.")

    supabase.table("users").insert({
        "username": data.username,
        "public_key": data.publicKey,
    }).execute()

    return {"success": True, "message": "Account created."}


@app.get("/api/challenge")
def get_challenge(username: str):
    result = supabase.table("users").select("username").eq("username", username).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="No account with this username.")

    challenge_value = base64.b64encode(os.urandom(32)).decode()
    challenges[username] = {"value": challenge_value, "expires": time.time() + CHALLENGE_TTL_SECONDS}
    return {"challenge": challenge_value}


@app.post("/api/login-verify")
def login_verify(data: LoginVerifyRequest):
    record = challenges.get(data.username)
    if not record or time.time() > record["expires"]:
        raise HTTPException(status_code=400, detail="Challenge expired. Request a new one.")

    result = supabase.table("users").select("public_key").eq("username", data.username).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="No account with this username.")

    public_key_b64 = result.data[0]["public_key"]

    try:
        raw_point = base64.b64decode(public_key_b64)
        x_y_bytes = raw_point[1:]
        vk = VerifyingKey.from_string(x_y_bytes, curve=NIST256p)

        signature_bytes = base64.b64decode(data.signature)
        challenge_bytes = record["value"].encode()

        vk.verify(signature_bytes, challenge_bytes, hashfunc=hashlib.sha256)
    except (BadSignatureError, ValueError, Exception):
        raise HTTPException(status_code=401, detail="Signature verification failed.")

    del challenges[data.username]
    return {"success": True, "message": "Login successful."}


@app.get("/")
def root():
    return {"status": "Fortress backend running"}