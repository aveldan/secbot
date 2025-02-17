from contextlib import asynccontextmanager
from fastapi import FastAPI
import os

from app.api.router import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    api_prefix = os.getenv("API_PREFIX", "")
    app.include_router(router, prefix=api_prefix)

    yield

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    return "Hello"