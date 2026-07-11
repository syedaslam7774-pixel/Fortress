import base64
import os
import time
import hashlib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase = None
init_error = None
try:
    import importlib
    supabase_module = importlib.import_module("supabase")
    create_client = supabase_module.create_client
    if not SUPABASE_URL or not SUPABASE_KEY:
        init_error = "Missing SUPABASE_URL or SUPABASE_KEY environment variable in Vercel."
    else:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    init_error = f"Startup error: {str(e)}"

challenges = {}
CHALLENGE_TTL_SECONDS = 60


class RegisterRequest(BaseModel):
    username: str
    publicKey: str


class LoginVerifyRequest(BaseModel):
    username: str
    signature: str


@app.get("/")
def root():
    return {"status": "running", "init_error": init_error}


@app.post("/api/register")
def register(data: RegisterRequest):
    if init_error:
        raise HTTPException(status_code=500, detail=init_error)
    try:
        existing = supabase.table("users").select("username").eq("username", data.username).execute()
        if existing.data:
            raise HTTPException(status_code=409, detail="Username already taken.")
        supabase.table("users").insert({
            "username": data.username,
            "public_key": data.publicKey,
        }).execute()
        return {"success": True, "message": "Account created."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Register error: {str(e)}")


@app.get("/api/challenge")
def get_challenge(username: str):
    if init_error:
        raise HTTPException(status_code=500, detail=init_error)
    try:
        result = supabase.table("users").select("username").eq("username", username).execute()
        if not result.data:
            raise HTTPException(status_code=404, detail="No account with this username.")
        challenge_value = base64.b64encode(os.urandom(32)).decode()
        challenges[username] = {"value": challenge_value, "expires": time.time() + CHALLENGE_TTL_SECONDS}
        return {"challenge": challenge_value}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Challenge error: {str(e)}")


@app.post("/api/login-verify")
def login_verify(data: LoginVerifyRequest):
    if init_error:
        raise HTTPException(status_code=500, detail=init_error)
    try:
        from ecdsa import VerifyingKey, NIST256p, BadSignatureError

        record = challenges.get(data.username)
        if not record or time.time() > record["expires"]:
            raise HTTPException(status_code=400, detail="Challenge expired. Request a new one.")

        result = supabase.table("users").select("public_key").eq("username", data.username).execute()
        if not result.data:
            raise HTTPException(status_code=404, detail="No account with this username.")

        public_key_b64 = result.data[0]["public_key"]
        raw_point = base64.b64decode(public_key_b64)
        x_y_bytes = raw_point[1:]
        vk = VerifyingKey.from_string(x_y_bytes, curve=NIST256p)

        signature_bytes = base64.b64decode(data.signature)
        challenge_bytes = record["value"].encode()

        try:
            vk.verify(signature_bytes, challenge_bytes, hashfunc=hashlib.sha256)
        except BadSignatureError:
            raise HTTPException(status_code=401, detail="Wrong password.")

        del challenges[data.username]
        return {"success": True, "message": "Login successful."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")