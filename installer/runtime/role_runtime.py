import argparse,json,os,time,hashlib
from datetime import datetime,timezone

def now(): return datetime.now(timezone.utc).isoformat()
def readj(p):
    try:
        with open(p,'r',encoding='utf-8-sig') as f:return json.load(f)
    except Exception:return {}
def writej(p,o):
    os.makedirs(os.path.dirname(p),exist_ok=True)
    tmp=p+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: json.dump(o,f,ensure_ascii=False,indent=2)
    os.replace(tmp,p)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--role',required=True);ap.add_argument('--install-root',required=True);ap.add_argument('--data-root',required=True);a=ap.parse_args()
    role_dir=os.path.join(a.data_root,'roles',a.role);hb=os.path.join(role_dir,'heartbeat.json')
    while True:
        sec=readj(os.path.join(a.data_root,'host-security.json'));contract=readj(os.path.join(a.data_root,'system-contract.json'))
        root=bool(sec.get('root_attested')); state=str(contract.get('state','UNATTACHED'))
        mode='OPERATIONAL' if root and state=='OPERATIONAL' else 'CONTAINED_READ_ONLY'
        writej(hb,{'schema':1,'role':a.role,'pid':os.getpid(),'timestamp_utc':now(),'mode':mode,'root_attested':root,'contract_state':state})
        time.sleep(5)
if __name__=='__main__': main()
