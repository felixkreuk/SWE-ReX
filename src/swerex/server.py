#!/usr/bin/env python3

import argparse
import asyncio
import logging
import shutil
import signal
import tempfile
import traceback
import zipfile
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from starlette.exceptions import HTTPException as StarletteHTTPException

from swerex import __version__
from swerex.runtime.abstract import (
    Action,
    CloseResponse,
    CloseSessionRequest,
    Command,
    CreateSessionRequest,
    ReadFileRequest,
    UploadResponse,
    WriteFileRequest,
    _ExceptionTransfer,
)
from swerex.runtime.local import LocalRuntime

logging.basicConfig(
    filename='server.log',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI()
runtime = LocalRuntime()

AUTH_TOKEN = ""
api_key_header = APIKeyHeader(name="X-API-Key")


def serialize_model(model):
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


@app.middleware("http")
async def authenticate(request: Request, call_next):
    """Authenticate requests with an API key (if set)."""
    if AUTH_TOKEN:
        api_key = await api_key_header(request)
        if api_key != AUTH_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid API Key")
    return await call_next(request)


@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception):
    """We catch exceptions that are thrown by the runtime, serialize them to JSON and
    return them to the client so they can reraise them in their own code.
    """
    if isinstance(exc, (HTTPException, StarletteHTTPException)):
        return await http_exception_handler(request, exc)
    extra_info = getattr(exc, "extra_info", {})
    _exc = _ExceptionTransfer(
        message=str(exc),
        class_path=type(exc).__module__ + "." + type(exc).__name__,
        traceback=traceback.format_exc(),
        extra_info=extra_info,
    )
    return JSONResponse(status_code=511, content={"swerexception": _exc.model_dump()})


@app.get("/")
async def root():
    return {"message": "hello world"}


@app.get("/is_alive")
async def is_alive():
    return serialize_model(await runtime.is_alive())


@app.post("/create_session")
async def create_session(request: CreateSessionRequest):
    return serialize_model(await runtime.create_session(request))


@app.post("/run_in_session")
async def run(action: Action):
    return serialize_model(await runtime.run_in_session(action))


@app.post("/close_session")
async def close_session(request: CloseSessionRequest):
    return serialize_model(await runtime.close_session(request))


@app.post("/execute")
async def execute(command: Command):
    return serialize_model(await runtime.execute(command))


@app.post("/read_file")
async def read_file(request: ReadFileRequest):
    return serialize_model(await runtime.read_file(request))


@app.post("/write_file")
async def write_file(request: WriteFileRequest):
    return serialize_model(await runtime.write_file(request))


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    target_path: str = Form(...),  # type: ignore
    unzip: bool = Form(False),
):
    target_path: Path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    # First save the file to a temporary directory and potentially unzip it.
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / "temp_file_transfer"
        try:
            with open(file_path, "wb") as f:
                f.write(await file.read())
        finally:
            await file.close()
        if unzip:
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(target_path)
            file_path.unlink()
        else:
            shutil.move(file_path, target_path)
    return UploadResponse()


@app.post("/close")
async def close():
    await runtime.close()
    return CloseResponse()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run the SWE-ReX server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--auth-token", required=True)
    return p


async def serve_once(host: str, port: int) -> None:
    config = uvicorn.Config(app, host=host, port=port)
    server = uvicorn.Server(config)
    loop = asyncio.get_running_loop()

    loop.add_signal_handler(
        signal.SIGUSR1,
        lambda: setattr(server, "should_exit", True)
    )
    await server.serve()  # ← blocks until should_exit is True

def main() -> None:
    i = 0
    args = build_arg_parser().parse_args()
    while True:
        logging.info(f"Starting server, iteation: {i}")
        asyncio.run(serve_once(args.host, args.port))
        i += 1

if __name__ == "__main__":
    main()
