import os
from datetime import datetime, timezone
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from jose import jwt, JWTError

# --- Configuration ---
# Use a default for development ONLY if explicitly allowed, 
# but here we follow the "Weakness 3" fix: No hardcoded demo secrets.
SECRET_KEY = os.environ.get("SENTINEL_JWT_SECRET")
ALGORITHM = os.environ.get("SENTINEL_JWT_ALGORITHM", "HS256")

# Note: We don't raise RuntimeError here because it might break 
# other scripts that import this but don't need JWT (like training).
# Instead, we validate at the entry point (main.py).

security = HTTPBearer()

def verify_token(credentials=Depends(security)):
    if not SECRET_KEY:
        raise HTTPException(status_code=500, detail="JWT Configuration Error: SECRET_KEY not set")
    
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # jose.jwt handles 'exp' automatically if present, but we can be explicit
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Token has expired")
            
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid or malformed token")