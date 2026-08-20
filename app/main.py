import base64, hashlib, json, os, random, time
from datetime import datetime, timezone
from typing import List

import firebase_admin
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from firebase_admin import auth, credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from .parser import parse_pdf_bytes

APP_NAME='SV Tech Multi-Firebase PDF Backend'
MAX_PDF_MB=int(os.getenv('MAX_PDF_MB','100'))
WRITE_BATCH_SIZE=max(50,min(450,int(os.getenv('WRITE_BATCH_SIZE','250'))))
WRITE_PAUSE_MS=max(0,int(os.getenv('WRITE_PAUSE_MS','120')))
WRITE_MAX_ATTEMPTS=max(3,int(os.getenv('WRITE_MAX_ATTEMPTS','8')))
ADMIN_EMAILS={x.strip().lower() for x in os.getenv('ADMIN_EMAILS','').split(',') if x.strip()}
SKIP_AUTH=os.getenv('SKIP_AUTH','').lower() in {'1','true','yes'}

PRIMARY_INFO=None
def init_primary():
    global PRIMARY_INFO
    if firebase_admin._apps: return
    raw=os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON','').strip()
    if raw:
        PRIMARY_INFO=json.loads(raw)
        firebase_admin.initialize_app(credentials.Certificate(PRIMARY_INFO))
        return
    path=os.getenv('GOOGLE_APPLICATION_CREDENTIALS','').strip()
    if path:
        with open(path,'r',encoding='utf-8') as f: PRIMARY_INFO=json.load(f)
        firebase_admin.initialize_app(credentials.Certificate(PRIMARY_INFO)); return
    raise RuntimeError('FIREBASE_SERVICE_ACCOUNT_JSON is required')
init_primary()
control_db=firestore.client()

def cipher():
    material=(PRIMARY_INFO or {}).get('private_key','') + '|' + (PRIMARY_INFO or {}).get('project_id','')
    key=base64.urlsafe_b64encode(hashlib.sha256(material.encode()).digest())
    return Fernet(key)
CIPHER=cipher()

def encrypt_json(obj): return CIPHER.encrypt(json.dumps(obj,separators=(',',':')).encode()).decode()
def decrypt_json(text): return json.loads(CIPHER.decrypt(text.encode()).decode())

def clean_id(s):
    out=''.join(ch.lower() if ch.isalnum() else '-' for ch in str(s).strip())
    return '-'.join(x for x in out.split('-') if x)[:80] or 'firebase'

def registry_ref(fid): return control_db.collection('_sv_firebase_registry').document(fid)

def get_registry_doc(fid):
    if fid in ('','primary',None): return None
    snap=registry_ref(fid).get()
    if not snap.exists: raise HTTPException(404,'Firebase configuration পাওয়া যায়নি')
    return snap.to_dict()

def target_db(fid='primary'):
    if fid in ('','primary',None): return control_db
    reg=get_registry_doc(fid)
    if not reg.get('enabled',True): raise HTTPException(400,'এই Firebase disabled আছে')
    app_name='target_'+clean_id(fid)
    try: app_obj=firebase_admin.get_app(app_name)
    except ValueError:
        info=decrypt_json(reg['service_account_enc'])
        app_obj=firebase_admin.initialize_app(credentials.Certificate(info),name=app_name)
    return firestore.client(app=app_obj)

app=FastAPI(title=APP_NAME,version='8.0.0')
origins=[x.strip() for x in os.getenv('ALLOWED_ORIGINS','*').split(',') if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins or ['*'],allow_credentials=False,allow_methods=['GET','POST','DELETE','OPTIONS'],allow_headers=['*'])

async def current_user(authorization: str|None=Header(default=None)):
    if SKIP_AUTH: return {'email':'local@test','uid':'local'}
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(401,'Admin login token পাওয়া যায়নি')
    try: decoded=auth.verify_id_token(authorization.split(' ',1)[1].strip())
    except Exception as e: raise HTTPException(401,'Firebase login token invalid') from e
    email=str(decoded.get('email','')).lower()
    if ADMIN_EMAILS and email not in ADMIN_EMAILS: raise HTTPException(403,'এই account-এর API permission নেই')
    return decoded

def safe_doc_id(row):
    voter=str(row.get('voter_no','')).strip()
    if voter: return ('v_'+voter).replace('/','_')[:1400]
    basis=str(row.get('record_key') or '|'.join(str(row.get(k,'')) for k in ('district_name','upazila_name','source_file','serial_no')))
    digest=hashlib.sha1(basis.encode()).hexdigest()[:20]
    serial=''.join(ch if ch.isalnum() or ch in '_-' else '_' for ch in str(row.get('serial_no','row')))
    return f's_{digest}_{serial[:80]}'

def chunks(seq,n):
    for i in range(0,len(seq),n): yield seq[i:i+n]

def commit_retry(batch):
    last=None
    for attempt in range(WRITE_MAX_ATTEMPTS):
        try: return batch.commit()
        except Exception as exc:
            last=exc; text=f'{type(exc).__name__}: {exc}'.lower()
            retryable=any(x in text for x in ('resourceexhausted','quota exceeded','429','503','deadline','aborted','too many requests'))
            if not retryable or attempt==WRITE_MAX_ATTEMPTS-1: raise
            time.sleep(min(20.0,1.5*(2**attempt))+random.uniform(0,.8))
    raise last

def write_rows(rows,db):
    written=batches=0; total=len(rows)
    items=[(db.collection('records').document(safe_doc_id(r)),r) for r in rows]
    for part in chunks(items,WRITE_BATCH_SIZE):
        b=db.batch()
        for ref,row in part: b.set(ref,row,merge=True)
        commit_retry(b); written+=len(part); batches+=1
        print(f'UPLOAD_PROGRESS {written}/{total}',flush=True)
        if WRITE_PAUSE_MS: time.sleep(WRITE_PAUSE_MS/1000)
    return written,batches

@app.get('/health')
def health(): return {'ok':True,'service':APP_NAME,'parser':'PY-RENDER-V8-MULTI-FIREBASE','write_mode':'selected_firebase_chunked_upsert','batch_size':WRITE_BATCH_SIZE,'max_pdf_mb':MAX_PDF_MB}

@app.get('/firebase/public-registry')
def public_registry():
    out=[]
    for s in control_db.collection('_sv_firebase_registry').stream():
        d=s.to_dict()
        if d.get('enabled',True): out.append({'id':s.id,'name':d.get('name',s.id),'config':d.get('public_config',{})})
    return {'ok':True,'firebases':out}

@app.get('/firebase/list')
def firebase_list(user=Depends(current_user)):
    out=[{'id':'primary','name':'Primary Firebase','project_id':(PRIMARY_INFO or {}).get('project_id','primary'),'enabled':True,'primary':True}]
    for s in control_db.collection('_sv_firebase_registry').stream():
        d=s.to_dict(); out.append({'id':s.id,'name':d.get('name',s.id),'project_id':d.get('project_id',''),'enabled':d.get('enabled',True),'primary':False})
    return {'ok':True,'firebases':out}

@app.post('/firebase/add')
async def firebase_add(name:str=Form(...),public_config:str=Form(...),service_account:str=Form(...),user=Depends(current_user)):
    try: pub=json.loads(public_config); svc=json.loads(service_account)
    except Exception as e: raise HTTPException(400,'Firebase config বা Service Account JSON সঠিক নয়') from e
    project_id=str(pub.get('projectId') or svc.get('project_id') or '').strip()
    if not project_id: raise HTTPException(400,'projectId পাওয়া যায়নি')
    if svc.get('project_id') and svc.get('project_id')!=project_id: raise HTTPException(400,'Web config এবং Service Account একই project-এর নয়')
    fid=clean_id(project_id)
    # Validate credential before saving.
    test_name='validate_'+fid
    try:
        try: test_app=firebase_admin.get_app(test_name)
        except ValueError: test_app=firebase_admin.initialize_app(credentials.Certificate(svc),name=test_name)
        firestore.client(app=test_app).collection('records').limit(1).get()
    except Exception as e: raise HTTPException(400,f'Firebase credential/Firestore connect হয়নি: {e}') from e
    registry_ref(fid).set({'name':name.strip() or project_id,'project_id':project_id,'public_config':pub,'service_account_enc':encrypt_json(svc),'enabled':True,'created_at':datetime.now(timezone.utc).isoformat(),'created_by':user.get('email','')},merge=True)
    return {'ok':True,'id':fid,'name':name.strip() or project_id,'project_id':project_id}

@app.post('/firebase/toggle')
async def firebase_toggle(firebase_id:str=Form(...),enabled:str=Form(...),user=Depends(current_user)):
    if firebase_id=='primary': raise HTTPException(400,'Primary Firebase disable করা যাবে না')
    registry_ref(firebase_id).set({'enabled':enabled.lower() in {'1','true','yes','on'}},merge=True)
    return {'ok':True}

@app.get('/firebase/stats')
def firebase_stats(firebase_id:str='primary',user=Depends(current_user)):
    db=target_db(firebase_id); docs=list(db.collection('records').stream()); a=[x.to_dict() for x in docs]
    return {'ok':True,'total':len(a),'districts':len(set(x.get('district_name','') for x in a)),'upazilas':len(set((x.get('district_name',''),x.get('upazila_name','')) for x in a))}

@app.get('/firebase/count')
def firebase_count(firebase_id:str='primary',district:str='',upazila:str='',user=Depends(current_user)):
    q=target_db(firebase_id).collection('records')
    if district: q=q.where(filter=FieldFilter('district_name','==',district))
    if upazila: q=q.where(filter=FieldFilter('upazila_name','==',upazila))
    return {'ok':True,'count':sum(1 for _ in q.stream())}

@app.delete('/firebase/records')
def firebase_delete_records(firebase_id:str='primary',district:str='',upazila:str='',user=Depends(current_user)):
    if not district or not upazila: raise HTTPException(400,'জেলা ও উপজেলা প্রয়োজন')
    db=target_db(firebase_id); q=db.collection('records').where(filter=FieldFilter('district_name','==',district)).where(filter=FieldFilter('upazila_name','==',upazila)); docs=list(q.stream()); deleted=0
    for part in chunks(docs,400):
        b=db.batch()
        for s in part: b.delete(s.reference)
        commit_retry(b); deleted+=len(part)
    return {'ok':True,'deleted':deleted}

async def read_pdf(file:UploadFile):
    data=await file.read()
    if not data: raise HTTPException(400,'PDF file খালি')
    if len(data)>MAX_PDF_MB*1024*1024: raise HTTPException(413,f'PDF সর্বোচ্চ {MAX_PDF_MB} MB হতে পারবে')
    return data

@app.post('/preview')
async def preview(district:str=Form(...),upazila:str=Form(...),file:UploadFile=File(...),user=Depends(current_user)):
    data=await read_pdf(file)
    try: rows=parse_pdf_bytes(data,district.strip(),upazila.strip(),file.filename)
    except Exception as e: raise HTTPException(422,f'PDF parse করা যায়নি: {e}') from e
    if not rows: raise HTTPException(422,'PDF থেকে কোনো Record শনাক্ত করা যায়নি')
    raw=sum(1 for r in rows if r.get('parse_status')=='raw_preserved')
    return {'ok':True,'records_detected':len(rows),'raw_preserved':raw,'preview':rows[:20],'parser':'PY-RENDER-V8-MULTI-FIREBASE'}

@app.post('/upload')
async def upload(district:str=Form(...),upazila:str=Form(...),firebase_id:str=Form('primary'),file:UploadFile=File(...),user=Depends(current_user)):
    data=await read_pdf(file)
    try: rows=parse_pdf_bytes(data,district.strip(),upazila.strip(),file.filename)
    except Exception as e: raise HTTPException(422,f'PDF parse করা যায়নি: {e}') from e
    if not rows: raise HTTPException(422,'PDF থেকে কোনো Record শনাক্ত করা যায়নি')
    db=target_db(firebase_id)
    try: written,batches=write_rows(rows,db)
    except Exception as e: raise HTTPException(500,f'Firestore write failed: {type(e).__name__}: {e}') from e
    raw=sum(1 for r in rows if r.get('parse_status')=='raw_preserved')
    log={'firebase_id':firebase_id,'district_name':district.strip(),'upazila_name':upazila.strip(),'file_name':file.filename,'records_detected':len(rows),'records_written':written,'batch_commits':batches,'records_added':written,'records_updated':0,'records_unchanged':0,'records_skipped':0,'raw_preserved':raw,'created_at':datetime.now(timezone.utc).isoformat(),'uploaded_by':user.get('email',''),'parser':'PY-RENDER-V8-MULTI-FIREBASE'}
    db.collection('pdf_imports').document('import_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')).set(log)
    return {'ok':True,**log}
