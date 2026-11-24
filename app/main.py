"""FastAPI application for LeakLens."""

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.github_fetcher import GitHubFetchError, fetch_common_files
from app.scanner import scan_sources, scan_text
from app.schemas import (
    MAX_CONTENT_LENGTH,
    HealthResponse,
    RepoScanRequest,
    ScanSummary,
    TextScanRequest,
)

BASE_DIR = Path(__file__).resolve().parent.parent
ALLOWED_EXTENSIONS = {".env", ".txt", ".json", ".yml", ".py", ".js"}

app = FastAPI(title="LeakLens", description="Scan text and public repositories for leaked secrets.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    """Serve the single-page frontend."""
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Return a lightweight service health check."""
    return HealthResponse(status="ok")


@app.post("/api/scan/text", response_model=ScanSummary)
async def scan_text_endpoint(request: TextScanRequest) -> ScanSummary:
    """Scan pasted text."""
    return scan_text(request.content, request.filename)


@app.post("/api/scan/file", response_model=ScanSummary)
async def scan_file_endpoint(file: UploadFile = File(...)) -> ScanSummary:
    """Scan a supported uploaded file up to one megabyte."""
    filename = Path(file.filename or "").name
    is_env_file = filename.lower() == ".env" or filename.lower().startswith(".env.")
    if not is_env_file and Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type. Use .env, .txt, .json, .yml, .py, or .js.",
        )
    raw_content = await file.read(MAX_CONTENT_LENGTH + 1)
    if len(raw_content) > MAX_CONTENT_LENGTH:
        raise HTTPException(status_code=413, detail="File exceeds the 1 MB upload limit.")
    try:
        content = raw_content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=400, detail="Upload must be a UTF-8 text file.") from error
    return scan_text(content, filename)


@app.post("/api/scan/repo", response_model=ScanSummary)
async def scan_repo_endpoint(request: RepoScanRequest) -> ScanSummary:
    """Scan common configuration files in a public GitHub repository."""
    try:
        sources = await fetch_common_files(request.repo_url)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except GitHubFetchError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return scan_sources(sources)
