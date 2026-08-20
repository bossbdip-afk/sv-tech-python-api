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
primary_db=firestore.client()

def init_registry_db():
    # Keep the Firebase registry off the primary project so a primary read-quota
    # exhaustion cannot break Firebase Manager. Prefer an explicit registry
    # credential; otherwise auto-pick the first extra FIREBASE_SERVICE_ACCOUNT_* env.
    raw=os.getenv('FIREBASE_REGISTRY_SERVICE_ACCOUNT_JSON','').strip()
    env_key='FIREBASE_REGISTRY_SERVICE_ACCOUNT_JSON'
    info=None
    if raw:
        try: info=json.loads(raw)
        except Exception as e: raise RuntimeError('FIREBASE_REGISTRY_SERVICE_ACCOUNT_JSON is invalid JSON') from e
    if info is None:
        candidates=[]
        for key,val in os.environ.items():
            if not key.startswith('FIREBASE_SERVICE_ACCOUNT_') or key=='FIREBASE_SERVICE_ACCOUNT_JSON':
                continue
            try: obj=json.loads(str(val or '').strip())
            except Exception: continue
            if obj.get('project_id'): candidates.append((key,obj))
        candidates.sort(key=lambda x:x[0])
        if candidates:
            env_key,info=candidates[0]
    if info is None:
        return primary_db, 'primary'
    try: app_obj=firebase_admin.get_app('registry_control')
    except ValueError:
        app_obj=firebase_admin.initialize_app(credentials.Certificate(info),name='registry_control')
    return firestore.client(app=app_obj), env_key

registry_db, REGISTRY_SOURCE = init_registry_db()

def _env_firebase_accounts():
    out={}
    for key,val in os.environ.items():
        if not key.startswith('FIREBASE_SERVICE_ACCOUNT_') or key=='FIREBASE_SERVICE_ACCOUNT_JSON':
            continue
        raw=str(val or '').strip()
        if not raw: continue
        try: info=json.loads(raw)
        except Exception: continue
        project_id=str(info.get('project_id') or '').strip()
        if not project_id: continue
        out[project_id]={'env_key':key,'info':info}
    return out

def _registry_docs_safe():
    out={}
    try:
        for snap in registry_db.collection('_sv_firebase_registry').stream():
            d=snap.to_dict() or {}
            out[snap.id]=d
    except Exception as exc:
        print(f'REGISTRY_LIST_FALLBACK {type(exc).__name__}: {exc}',flush=True)
    return out

def firebase_catalog(include_disabled=True):
    """Merge Firestore registry + Render env credentials. Registry failure must not hide configured Firebase projects."""
    primary_project=str((PRIMARY_INFO or {}).get('project_id') or 'primary')
    items=[{'id':'primary','name':'Primary Firebase','project_id':primary_project,'enabled':True,'primary':True,'service_env_key':'FIREBASE_SERVICE_ACCOUNT_JSON'}]
    regs=_registry_docs_safe()
    by_project={str((d or {}).get('project_id') or '').strip():(fid,d) for fid,d in regs.items() if str((d or {}).get('project_id') or '').strip()}
    seen={primary_project}
    for project_id,entry in sorted(_env_firebase_accounts().items()):
        if project_id in seen: continue
        seen.add(project_id)
        if project_id in by_project:
            fid,d=by_project[project_id]
            enabled=bool(d.get('enabled',True))
            name=str(d.get('name') or project_id)
            env_key=str(d.get('service_env_key') or entry['env_key'])
            pub=d.get('public_config') or {}
        else:
            fid=clean_id(project_id)
            enabled=True; name=project_id; env_key=entry['env_key']; pub={}
        if include_disabled or enabled:
            items.append({'id':fid,'name':name,'project_id':project_id,'enabled':enabled,'primary':False,'service_env_key':env_key,'public_config':pub})
    # Registry records whose env var is temporarily unavailable are still visible in Manager.
    for fid,d in regs.items():
        project_id=str(d.get('project_id') or '').strip()
        if not project_id or project_id in seen: continue
        enabled=bool(d.get('enabled',True))
        if include_disabled or enabled:
            items.append({'id':fid,'name':str(d.get('name') or fid),'project_id':project_id,'enabled':enabled,'primary':False,'service_env_key':str(d.get('service_env_key') or ''),'public_config':d.get('public_config') or {}})
    return items

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

def registry_ref(fid): return registry_db.collection('_sv_firebase_registry').document(fid)

def get_registry_doc(fid):
    if fid in ('','primary',None): return None
    try:
        snap=registry_ref(fid).get()
        if snap.exists: return snap.to_dict() or {}
    except Exception as exc:
        print(f'REGISTRY_GET_FALLBACK {fid}: {type(exc).__name__}: {exc}',flush=True)
    # Fall back to Render env catalog so a registry quota/outage cannot break routing.
    for item in firebase_catalog(include_disabled=True):
        if item['id']==fid or item['project_id']==fid:
            return {'name':item['name'],'project_id':item['project_id'],'enabled':item['enabled'],'service_env_key':item.get('service_env_key',''),'public_config':item.get('public_config',{})}
    raise HTTPException(404,'Firebase configuration পাওয়া যায়নি')

def _service_account_from_registry(reg):
    env_key=str(reg.get('service_env_key') or '').strip()
    if env_key:
        raw=os.getenv(env_key,'').strip()
        if not raw:
            raise HTTPException(500,f'Render Environment variable {env_key} পাওয়া যায়নি')
        try:
            return json.loads(raw)
        except Exception as e:
            raise HTTPException(500,f'{env_key} JSON সঠিক নয়') from e
    enc=reg.get('service_account_enc')
    if enc:
        return decrypt_json(enc)
    raise HTTPException(500,'এই Firebase-এর secure credential পাওয়া যায়নি')

def _find_service_account_env(project_id):
    matches=[]
    for key,val in os.environ.items():
        if not key.startswith('FIREBASE_SERVICE_ACCOUNT_') or key=='FIREBASE_SERVICE_ACCOUNT_JSON':
            continue
        raw=str(val or '').strip()
        if not raw:
            continue
        try:
            obj=json.loads(raw)
        except Exception:
            continue
        if str(obj.get('project_id') or '').strip()==project_id:
            matches.append((key,obj))
    if not matches:
        return None,None
    matches.sort(key=lambda x:x[0])
    return matches[0]



_RECORD_STORE_CACHE={}
_RECORD_FIELD_ALIASES={
    'voter_no':('voter_no','voter','voterNo','voter_number','voterNumber'),
    'name':('name','full_name','fullName','voter_name','voterName'),
    'father_name':('father_name','father','fatherName'),
    'mother_name':('mother_name','mother','motherName'),
    'birth_date':('birth_date','dob','birthDate','date_of_birth'),
    'district_name':('district_name','district','districtName'),
    'upazila_name':('upazila_name','upazila','upazilla','upazilaName','thana'),
}

def _pick_record_fields(sample):
    sample=sample or {}
    keys=set(sample.keys())
    out={}
    for std,aliases in _RECORD_FIELD_ALIASES.items():
        out[std]=next((x for x in aliases if x in keys),std)
    return out

def _looks_like_voter_row(row):
    if not isinstance(row,dict) or not row: return False
    keys=set(row.keys())
    voter=any(k in keys for k in _RECORD_FIELD_ALIASES['voter_no'])
    name=any(k in keys for k in _RECORD_FIELD_ALIASES['name'])
    area=any(k in keys for k in _RECORD_FIELD_ALIASES['district_name']) or any(k in keys for k in _RECORD_FIELD_ALIASES['upazila_name'])
    family=any(k in keys for k in _RECORD_FIELD_ALIASES['father_name']) or any(k in keys for k in _RECORD_FIELD_ALIASES['mother_name'])
    return voter and name and (area or family)

def _sample_collection(col):
    try:
        docs=list(col.limit(3).stream())
    except Exception:
        return None,False
    if not docs: return {},False
    rows=[d.to_dict() or {} for d in docs]
    sample=next((r for r in rows if _looks_like_voter_row(r)),rows[0])
    return sample,any(_looks_like_voter_row(r) for r in rows)

def record_store(db):
    """Return the configured voter collection without enumerating Firestore collections.

    V8.6 quota-safety rule: never call ``db.collections()`` to guess a legacy
    collection. The deployed V8.4 application used ``records`` for Primary and
    all managed Firebase projects, so keep that known-good path. An optional
    backend-only env override can be used for a genuinely different project
    without exposing anything to the frontend.
    """
    key=str(getattr(db,'project',None) or id(db))
    cached=_RECORD_STORE_CACHE.get(key)
    if cached: return cached

    project=str(getattr(db,'project',None) or '').strip()
    primary_project=str((PRIMARY_INFO or {}).get('project_id') or '').strip()
    env_name='FIREBASE_RECORD_COLLECTION_PRIMARY' if project and project==primary_project else 'FIREBASE_RECORD_COLLECTION'
    cname=str(os.getenv(env_name,'') or os.getenv('FIREBASE_RECORD_COLLECTION','') or 'records').strip() or 'records'
    col=db.collection(cname)
    fields={k:k for k in _RECORD_FIELD_ALIASES}
    result=(col,fields,cname)
    _RECORD_STORE_CACHE[key]=result
    return result

def _row_standardized(row,fields):
    d=dict(row or {})
    for std,actual in fields.items():
        if std not in d and actual in d: d[std]=d.get(actual)
    return d

def target_db(fid='primary'):
    if fid in ('','primary',None): return primary_db
    reg=get_registry_doc(fid)
    if not reg.get('enabled',True): raise HTTPException(400,'এই Firebase disabled আছে')
    app_name='target_'+clean_id(fid)
    try: app_obj=firebase_admin.get_app(app_name)
    except ValueError:
        info=_service_account_from_registry(reg)
        app_obj=firebase_admin.initialize_app(credentials.Certificate(info),name=app_name)
    return firestore.client(app=app_obj)

app=FastAPI(title=APP_NAME,version='8.6.0')
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
    col,_,_=record_store(db)
    items=[(col.document(safe_doc_id(r)),r) for r in rows]
    for part in chunks(items,WRITE_BATCH_SIZE):
        b=db.batch()
        for ref,row in part: b.set(ref,row,merge=True)
        commit_retry(b); written+=len(part); batches+=1
        print(f'UPLOAD_PROGRESS {written}/{total}',flush=True)
        if WRITE_PAUSE_MS: time.sleep(WRITE_PAUSE_MS/1000)
    # Keep compact distinct-area metadata so dashboard aggregation does not scan all records on every refresh.
    try:
        ref=db.collection('_sv_meta').document('stats')
        districts={str(r.get('district_name','')).strip() for r in rows if str(r.get('district_name','')).strip()}
        upazilas={(str(r.get('district_name','')).strip(),str(r.get('upazila_name','')).strip()) for r in rows if str(r.get('upazila_name','')).strip()}
        try:
            snap=ref.get(); oldm=(snap.to_dict() or {}) if snap.exists else {}
            districts |= {str(x).strip() for x in oldm.get('district_values',[]) if str(x).strip()}
            for x in oldm.get('upazila_values',[]):
                parts=str(x).split('|||',1)
                if len(parts)==2 and parts[1].strip(): upazilas.add((parts[0].strip(),parts[1].strip()))
        except Exception:
            pass
        ref.set({
            'district_values':sorted(districts),
            'upazila_values':sorted(d+'|||'+u for d,u in upazilas),
            'districts':len(districts),'upazilas':len(upazilas),
            'updated_at':datetime.now(timezone.utc).isoformat()
        },merge=True)
    except Exception as exc:
        print(f'META_UPDATE_SKIP {type(exc).__name__}: {exc}',flush=True)
    return written,batches

@app.get('/health')
def health(): return {'ok':True,'service':APP_NAME,'parser':'PY-RENDER-V8.6-PRIMARY-QUOTA-SAFE','write_mode':'selected_firebase_chunked_upsert_secure_env','registry_source':REGISTRY_SOURCE,'batch_size':WRITE_BATCH_SIZE,'max_pdf_mb':MAX_PDF_MB}



def _public_search_targets():
    targets=[]
    for item in firebase_catalog(include_disabled=False):
        try:
            targets.append((item['id'],item['name'],target_db(item['id'])))
        except Exception as exc:
            print(f'PUBLIC_SEARCH_TARGET_SKIP {item["id"]}: {type(exc).__name__}: {exc}',flush=True)
    return targets

@app.get('/public/search')
def public_search(district:str='',upazila:str='',name:str='',father:str='',mother:str='',dob:str=''):
    district=district.strip(); upazila=upazila.strip()
    if not district or not upazila:
        raise HTTPException(400,'জেলা ও উপজেলা প্রয়োজন')
    wanted={
        'name':name.strip().casefold(),
        'father_name':father.strip().casefold(),
        'mother_name':mother.strip().casefold(),
        'birth_date':dob.strip().casefold(),
    }
    rows=[]; errors=[]
    for fid,fname,dbx in _public_search_targets():
        try:
            col,fields,_=record_store(dbx)
            q=(col
               .where(filter=FieldFilter(fields['district_name'],'==',district))
               .where(filter=FieldFilter(fields['upazila_name'],'==',upazila)))
            for snap in q.stream():
                d=_row_standardized(snap.to_dict() or {},fields)
                ok=True
                for field,needle in wanted.items():
                    if needle and needle not in str(d.get(field,'')).strip().casefold():
                        ok=False; break
                if not ok:
                    continue
                d['_firebase_id']=fid
                d['_firebase_name']=fname
                rows.append(d)
        except Exception as exc:
            errors.append({'firebase_id':fid,'error':type(exc).__name__})
            print(f'PUBLIC_SEARCH_DB_ERROR {fid}: {type(exc).__name__}: {exc}',flush=True)
    uniq={}
    for d in rows:
        key=str(d.get('voter_no') or '').strip() or '|'.join(str(d.get(k,'')).strip() for k in ('name','father_name','birth_date','district_name','upazila_name'))
        if key not in uniq:
            uniq[key]=d
    return {'ok':True,'count':len(uniq),'results':list(uniq.values()),'errors':errors}

@app.get('/firebase/public-registry')
def public_registry():
    out=[]
    for item in firebase_catalog(include_disabled=False):
        if item['id']=='primary': continue
        cfg=item.get('public_config') or {}
        if cfg:
            out.append({'id':item['id'],'name':item['name'],'config':cfg})
    return {'ok':True,'firebases':out}

@app.get('/firebase/list')
def firebase_list(user=Depends(current_user)):
    return {'ok':True,'firebases':[{k:v for k,v in x.items() if k!='public_config' and k!='service_env_key'} for x in firebase_catalog(include_disabled=True)]}

@app.post('/firebase/add')
async def firebase_add(name:str=Form(...),public_config:str=Form(...),user=Depends(current_user)):
    try:
        pub=json.loads(public_config)
    except Exception as e:
        raise HTTPException(400,'Firebase Web Config JSON সঠিক নয়') from e
    project_id=str(pub.get('projectId') or '').strip()
    if not project_id:
        raise HTTPException(400,'Web Config-এ projectId পাওয়া যায়নি')
    env_key,svc=_find_service_account_env(project_id)
    if not env_key or not svc:
        raise HTTPException(400,'Render Environment-এ এই project-এর Service Account পাওয়া যায়নি। FIREBASE_SERVICE_ACCOUNT_... key-তে পুরো JSON save করে আবার চেষ্টা করুন।')
    fid=clean_id(project_id)
    test_name='validate_'+fid
    try:
        try: test_app=firebase_admin.get_app(test_name)
        except ValueError: test_app=firebase_admin.initialize_app(credentials.Certificate(svc),name=test_name)
        firestore.client(app=test_app).collection('records').limit(1).get()
    except Exception as e:
        raise HTTPException(400,f'Firebase credential/Firestore connect হয়নি: {e}') from e
    registry_ref(fid).set({
        'name':name.strip() or project_id,
        'project_id':project_id,
        'public_config':pub,
        'service_env_key':env_key,
        'enabled':True,
        'created_at':datetime.now(timezone.utc).isoformat(),
        'created_by':user.get('email','')
    },merge=True)
    return {'ok':True,'id':fid,'name':name.strip() or project_id,'project_id':project_id,'credential_source':'render_env','service_env_key':env_key}

@app.post('/firebase/toggle')
async def firebase_toggle(firebase_id:str=Form(...),enabled:str=Form(...),user=Depends(current_user)):
    if firebase_id=='primary': raise HTTPException(400,'Primary Firebase disable করা যাবে না')
    registry_ref(firebase_id).set({'enabled':enabled.lower() in {'1','true','yes','on'}},merge=True)
    return {'ok':True}

def query_count(q):
    # Firestore aggregation count avoids streaming every document.
    try:
        results=q.count().get()
        for item in results:
            # google-cloud-firestore versions return either AggregationResult
            # or a tuple/list containing one.
            obj=item[0] if isinstance(item,(tuple,list)) and item else item
            val=getattr(obj,'value',None)
            if val is not None: return int(val)
    except Exception:
        raise
    return 0


def _meta_area_sets(db, rebuild_if_missing=True):
    ref=db.collection('_sv_meta').document('stats')
    meta={}
    try:
        snap=ref.get()
        if snap.exists: meta=snap.to_dict() or {}
    except Exception:
        meta={}
    dvals={str(x).strip() for x in meta.get('district_values',[]) if str(x).strip()}
    uvals=set()
    for x in meta.get('upazila_values',[]):
        parts=str(x).split('|||',1)
        if len(parts)==2 and parts[1].strip(): uvals.add((parts[0].strip(),parts[1].strip()))
    if (dvals or uvals) or not rebuild_if_missing:
        return dvals,uvals

    # V8.6: never rebuild area metadata by streaming the entire records collection.
    # Historical upload logs are tiny compared with voter records and already carry
    # district/upazila, so recover metadata from those instead.
    try:
        q=db.collection('pdf_imports').select(['district_name','upazila_name']).limit(2000)
        for snap in q.stream():
            row=snap.to_dict() or {}
            d=str(row.get('district_name','')).strip(); u=str(row.get('upazila_name','')).strip()
            if d: dvals.add(d)
            if u: uvals.add((d,u))
        if dvals or uvals:
            ref.set({
                'district_values':sorted(dvals),
                'upazila_values':sorted(d+'|||'+u for d,u in uvals),
                'districts':len(dvals),'upazilas':len(uvals),
                'updated_at':datetime.now(timezone.utc).isoformat(),
                'source':'pdf_imports_v8_6'
            },merge=True)
            print(f'META_RECOVERED_FROM_IMPORTS {getattr(db,"project","")}: {len(dvals)} districts, {len(uvals)} upazilas',flush=True)
    except Exception as exc:
        print(f'META_IMPORT_RECOVERY_SKIP {type(exc).__name__}: {exc}',flush=True)
    return dvals,uvals

def _stats_for_db(db):
    col,_,_=record_store(db)
    total=query_count(col)
    dvals,uvals=_meta_area_sets(db,True)
    return total,dvals,uvals

@app.get('/firebase/stats')
def firebase_stats(firebase_id:str='primary',user=Depends(current_user)):
    try:
        total,dvals,uvals=_stats_for_db(target_db(firebase_id))
        return {'ok':True,'total':total,'districts':len(dvals),'upazilas':len(uvals)}
    except Exception as e:
        return {'ok':False,'total':0,'districts':0,'upazilas':0,'warning':f'stats unavailable: {type(e).__name__}'}

@app.get('/firebase/stats-all')
def firebase_stats_all(user=Depends(current_user)):
    total=0; districts=set(); upazilas=set(); sources=[]; errors=[]
    for item in firebase_catalog(include_disabled=False):
        try:
            t,ds,us=_stats_for_db(target_db(item['id']))
            total+=t; districts|=ds; upazilas|=us
            col,_,cname=record_store(target_db(item['id']))
            sources.append({'id':item['id'],'name':item['name'],'total':t,'collection':cname})
        except Exception as exc:
            errors.append({'id':item['id'],'name':item['name'],'error':type(exc).__name__})
            print(f'STATS_ALL_SKIP {item["id"]}: {type(exc).__name__}: {exc}',flush=True)
    return {'ok':True,'total':total,'districts':len(districts),'upazilas':len(upazilas),'sources':sources,'errors':errors}

@app.get('/firebase/areas')
def firebase_areas(firebase_id:str='primary',user=Depends(current_user)):
    try:
        ds,us=_meta_area_sets(target_db(firebase_id),True)
        _,_,cname=record_store(target_db(firebase_id))
        return {'ok':True,'districts':sorted(ds),'upazilas':[{'district':d,'upazila':u} for d,u in sorted(us)],'collection':cname}
    except Exception as exc:
        raise HTTPException(503,f'এলাকার তালিকা পাওয়া যায়নি: {type(exc).__name__}') from exc

@app.get('/firebase/count')
def firebase_count(firebase_id:str='primary',district:str='',upazila:str='',user=Depends(current_user)):
    db=target_db(firebase_id); col,fields,_=record_store(db); q=col
    if district: q=q.where(filter=FieldFilter(fields['district_name'],'==',district))
    if upazila: q=q.where(filter=FieldFilter(fields['upazila_name'],'==',upazila))
    return {'ok':True,'count':query_count(q)}

@app.delete('/firebase/records')
def firebase_delete_records(firebase_id:str='primary',district:str='',upazila:str='',user=Depends(current_user)):
    if not district or not upazila: raise HTTPException(400,'জেলা ও উপজেলা প্রয়োজন')
    db=target_db(firebase_id); col,fields,_=record_store(db); q=col.where(filter=FieldFilter(fields['district_name'],'==',district)).where(filter=FieldFilter(fields['upazila_name'],'==',upazila)); docs=list(q.stream()); deleted=0
    for part in chunks(docs,400):
        b=db.batch()
        for snap in part: b.delete(snap.reference)
        commit_retry(b); deleted+=len(part)
    # Rebuild compact area metadata after destructive delete so aggregate unique counts stay correct.
    try:
        db.collection('_sv_meta').document('stats').set({'district_values':[],'upazila_values':[],'districts':0,'upazilas':0},merge=True)
        _meta_area_sets(db,True)
    except Exception as exc:
        print(f'META_AFTER_DELETE_SKIP {type(exc).__name__}: {exc}',flush=True)
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
