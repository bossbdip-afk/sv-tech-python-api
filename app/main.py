import hashlib
import json
import os
import time
import random
from datetime import datetime, timezone
from typing import Iterable, List

import firebase_admin
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from firebase_admin import auth, credentials, firestore

from .parser import parse_pdf_bytes
APP_NAME = 'SV Tech PDF Backend'
MAX_PDF_MB = int(os.getenv('MAX_PDF_MB', '100'))
WRITE_BATCH_SIZE = max(50, min(450, int(os.getenv('WRITE_BATCH_SIZE', '250'))))
WRITE_PAUSE_MS = max(0, int(os.getenv('WRITE_PAUSE_MS', '120')))
WRITE_MAX_ATTEMPTS = max(3, int(os.getenv('WRITE_MAX_ATTEMPTS', '8')))
ADMIN_EMAILS = {x.strip().lower() for x in os.getenv('ADMIN_EMAILS', '').split(',') if x.strip()}
SKIP_AUTH = os.getenv('SKIP_AUTH', '').lower() in {'1', 'true', 'yes'}

def init_firebase():
    if firebase_admin._apps:
        return
    raw = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON', '').strip()
    if raw:
        info = json.loads(raw)
        firebase_admin.initialize_app(credentials.Certificate(info))
        return
    path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS', '').strip()
    if path:
        firebase_admin.initialize_app(credentials.ApplicationDefault())
        return
    raise RuntimeError('FIREBASE_SERVICE_ACCOUNT_JSON environment variable is required')

init_firebase()
db = firestore.client()
app = FastAPI(title=APP_NAME, version='7.0.0')

origins = [x.strip() for x in os.getenv('ALLOWED_ORIGINS', '*').split(',') if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ['*'],
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['*'],
)

async def current_user(authorization: str | None = Header(default=None)):
    if SKIP_AUTH:
        return {'email': 'local@test', 'uid': 'local'}
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='Admin login token পাওয়া যায়নি')
    token = authorization.split(' ', 1)[1].strip()
    try:
        decoded = auth.verify_id_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail='Firebase login token invalid') from e
    email = str(decoded.get('email', '')).lower()
    if ADMIN_EMAILS and email not in ADMIN_EMAILS:
        raise HTTPException(status_code=403, detail='এই account-এর API permission নেই')
    return decoded

def safe_doc_id(row: dict) -> str:
    voter = str(row.get('voter_no', '')).strip()
    if voter:
        return ('v_' + voter).replace('/', '_')[:1400]
    basis = str(row.get('record_key') or '|'.join(str(row.get(k,'')) for k in ('district_name','upazila_name','source_file','serial_no')))
    digest = hashlib.sha1(basis.encode('utf-8')).hexdigest()[:20]
    serial = ''.join(ch if ch.isalnum() or ch in '_-' else '_' for ch in str(row.get('serial_no','row')))
    return f's_{digest}_{serial[:80]}'

def chunks(seq: List, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i+n]


def comparable(d: dict):
    ignore = {'created_at'}
    return {k: v for k, v in d.items() if k not in ignore}


def _commit_batch_with_retry(batch, max_attempts: int | None = None):
    """Commit one Firestore batch with exponential backoff + jitter.

    This handles temporary 429/503/deadline errors. A hard daily Firestore
    quota still cannot be bypassed by application code.
    """
    attempts = max_attempts or WRITE_MAX_ATTEMPTS
    last_error = None
    for attempt in range(attempts):
        try:
            return batch.commit()
        except Exception as exc:
            last_error = exc
            text = f"{type(exc).__name__}: {exc}".lower()
            retryable = any(x in text for x in (
                'resourceexhausted', 'quota exceeded', '429',
                'serviceunavailable', '503', 'deadlineexceeded', 'deadline exceeded',
                'aborted', 'too many requests'
            ))
            if not retryable or attempt == attempts - 1:
                raise
            base = min(20.0, 1.5 * (2 ** attempt))
            time.sleep(base + random.uniform(0.0, 0.8))
    raise last_error


def write_rows(rows: List[dict]):
    """Large-PDF direct upsert with ZERO pre-read queries.

    Records are written with deterministic document IDs in conservative chunks.
    The method is idempotent: re-uploading after a partial failure overwrites the
    same document IDs instead of creating a second copy.
    """
    total = len(rows)
    written = 0
    batch_commits = 0
    write_items = [
        (db.collection('records').document(safe_doc_id(row)), row)
        for row in rows
    ]
    for part in chunks(write_items, WRITE_BATCH_SIZE):
        batch = db.batch()
        for ref, row in part:
            batch.set(ref, row, merge=True)
        _commit_batch_with_retry(batch)
        written += len(part)
        batch_commits += 1
        print(f"UPLOAD_PROGRESS {written}/{total} records ({batch_commits} batches)", flush=True)
        if WRITE_PAUSE_MS:
            time.sleep(WRITE_PAUSE_MS / 1000.0)
    return written, batch_commits


@app.get('/health')
def health():
    return {'ok': True, 'service': APP_NAME, 'parser': 'PY-RENDER-V7-LARGE-PDF', 'write_mode': 'large_pdf_chunked_upsert_no_preread', 'batch_size': WRITE_BATCH_SIZE, 'max_pdf_mb': MAX_PDF_MB}

async def read_pdf(file: UploadFile) -> bytes:
    if file.content_type not in ('application/pdf', 'application/octet-stream') and not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail='শুধু PDF file দিন')
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail='PDF file খালি')
    if len(data) > MAX_PDF_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f'PDF সর্বোচ্চ {MAX_PDF_MB} MB হতে পারবে')
    return data

@app.post('/preview')
async def preview(
    district: str = Form(...),
    upazila: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(current_user),
):
    data = await read_pdf(file)
    try:
        rows = parse_pdf_bytes(data, district.strip(), upazila.strip(), file.filename)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f'PDF parse করা যায়নি: {e}') from e
    if not rows:
        raise HTTPException(status_code=422, detail='PDF থেকে কোনো Record শনাক্ত করা যায়নি')
    raw_kept = sum(1 for r in rows if r.get('parse_status') == 'raw_preserved')
    return {
        'ok': True,
        'records_detected': len(rows),
        'raw_preserved': raw_kept,
        'preview': rows[:20],
        'parser': 'PY-RENDER-V7-LARGE-PDF',
    }

@app.post('/upload')
async def upload(
    district: str = Form(...),
    upazila: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(current_user),
):
    data = await read_pdf(file)
    try:
        rows = parse_pdf_bytes(data, district.strip(), upazila.strip(), file.filename)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f'PDF parse করা যায়নি: {e}') from e
    if not rows:
        raise HTTPException(status_code=422, detail='PDF থেকে কোনো Record শনাক্ত করা যায়নি')
    try:
        written, batch_commits = write_rows(rows)
    except Exception as e:
        text = f"{type(e).__name__}: {e}"
        if '429' in text or 'Quota' in text or 'ResourceExhausted' in text:
            raise HTTPException(
                status_code=429,
                detail='Firestore write quota/rate limit reached. এই version upload-এর আগে কোনো document read করে না; quota reset/upgrade ছাড়া hard write quota bypass করা যায় না.'
            ) from e
        raise HTTPException(status_code=500, detail=f'Firestore write failed: {text}') from e
    raw_kept = sum(1 for r in rows if r.get('parse_status') == 'raw_preserved')
    log = {
        'district_name': district.strip(), 'upazila_name': upazila.strip(), 'file_name': file.filename,
        'records_detected': len(rows), 'records_written': written, 'batch_commits': batch_commits,
        'records_added': written, 'records_updated': 0, 'records_unchanged': 0,
        'records_skipped': 0, 'raw_preserved': raw_kept,
        'created_at': datetime.now(timezone.utc).isoformat(), 'uploaded_by': user.get('email', ''),
        'parser': 'PY-RENDER-V7-LARGE-PDF — zero pre-read; chunked direct upsert',
        'write_mode': 'large_pdf_chunked_upsert_no_preread',
        'batch_size': WRITE_BATCH_SIZE,
    }
    db.collection('pdf_imports').document('import_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')).set(log)
    return {'ok': True, **log}
