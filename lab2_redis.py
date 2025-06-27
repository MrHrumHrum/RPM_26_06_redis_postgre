from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import bcrypt
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError
from datetime import datetime, timedelta, timezone
import asyncio
from redis.asyncio import Redis, from_url

app = FastAPI()


REDIS_URL = "redis://:eYVX7EwVmmxKPCDmwMtyKVge8oLd2t81@77.91.86.135:5540"
KEY_PREFIX = "kirsanov_"
redis = None


@app.on_event("startup")
async def startup():
    global redis
    redis = await from_url(REDIS_URL, encoding="utf-8", decode_responses=True)


@app.on_event("shutdown")
async def shutdown():
    await redis.close()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = "e3e46dc50be2a00ff15df3a07c267db5dcd433f4326b3283b4cab7c1c5187e61"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    password: str


class UserResponse(BaseModel):
    username: str
    email: str
    full_name: str | None = None


class Token(BaseModel):
    access_token: str
    token_type: str



def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_user(username: str) -> dict | None:
    return await redis.hgetall(f"{KEY_PREFIX}user:{username}")


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user or not verify_password(password, user['hashed_password']):
        return False
    return user


@app.post("/register/", response_model=UserResponse)
async def register_user(user: UserCreate):
    if await get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")

    if await redis.exists(f"{KEY_PREFIX}email:{user.email}"):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user.password)
    user_data = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name or "",
        "hashed_password": hashed_password
    }

    async with redis.pipeline() as pipe:
        await pipe.hset(f"{KEY_PREFIX}user:{user.username}", mapping=user_data)
        await pipe.set(f"{KEY_PREFIX}email:{user.email}", user.username)
        await pipe.execute()

    return UserResponse(**{k: v for k, v in user_data.items() if k != "hashed_password"})


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect credentials")

    access_token = create_access_token(
        data={"sub": user['username']},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/", response_model=list[UserResponse])
async def get_users(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    users = []
    async for key in redis.scan_iter(f"{KEY_PREFIX}user:*"):
        user_data = await redis.hgetall(key)
        users.append(UserResponse(
            username=user_data["username"],
            email=user_data["email"],
            full_name=user_data["full_name"] or None
        ))

    return users