import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Iterable, List

import firebase_admin
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from firebase_admin import auth, credentials, firestore

from .parser import parse_pdf_bytes

APP_NAME = 'SV Tech PDF Backend'
MAX_PDF_MB = int(os.getenv('MAX_PDF_MB', '40'))
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
app = FastAPI(title=APP_NAME, version='1.0.0')

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


def write_rows(rows: List[dict]):
    refs = [db.collection('records').document(safe_doc_id(r)) for r in rows]
    existing = {}
    for ref_chunk in chunks(refs, 400):
        for snap in db.get_all(ref_chunk):
            existing[snap.reference.path] = snap.to_dict() if snap.exists else None

    added = updated = unchanged = 0
    write_items = []
    for row, ref in zip(rows, refs):
        old = existing.get(ref.path)
        if old is None:
            added += 1
            write_items.append((ref, row))
        elif comparable(old) == comparable(row):
            unchanged += 1
        else:
            updated += 1
            write_items.append((ref, row))

    for part in chunks(write_items, 400):
        batch = db.batch()
        for ref, row in part:
            batch.set(ref, row, merge=True)
        batch.commit()
    return added, updated, unchanged


@app.get('/health')
def health():
    return {'ok': True, 'service': APP_NAME, 'parser': 'PY-RENDER-V1'}


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
        'parser': 'PY-RENDER-V1',
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

    added, updated, unchanged = write_rows(rows)
    raw_kept = sum(1 for r in rows if r.get('parse_status') == 'raw_preserved')
    log = {
        'district_name': district.strip(), 'upazila_name': upazila.strip(), 'file_name': file.filename,
        'records_detected': len(rows), 'records_added': added, 'records_updated': updated,
        'records_unchanged': unchanged, 'records_skipped': 0, 'raw_preserved': raw_kept,
        'created_at': datetime.now(timezone.utc).isoformat(), 'uploaded_by': user.get('email', ''),
        'parser': 'PY-RENDER-V1 — server-side FastAPI/PyMuPDF, raw preserved, no record drop',
    }
    db.collection('pdf_imports').document('import_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')).set(log)
    return {'ok': True, **log}
