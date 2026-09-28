import asyncio, json, sqlite3, re
from pathlib import Path
ROOT=Path(__file__).parent
SRC=(ROOT/'sandbox_app/app.py').read_text()
DB=ROOT/'knowledge.db'
conn=sqlite3.connect(DB)
conn.execute('drop table if exists findings')
conn.execute('create table findings(id integer primary key, agent text, hypothesis text, evidence text, status text)')
conn.commit()
roles=['web','api','auth','config','logic','data','dependency','filesystem','privacy','review']

def analyze(agent_id, role):
    # Static review checks; no exploit generation or external networking.
    out=[]
    if role in {'data','filesystem'}:
        if 'ALLOWED_USERS' not in SRC or 'user_id not in ALLOWED_USERS' not in SRC:
            out.append(('unvalidated identifier', 'missing allowlist validation'))
    if role=='auth' and 'ALLOWED_USERS' in SRC:
        out.append(('authentication boundary reviewed', 'allowlist validation present'))
    if role=='review':
        out.append(('independent verification required', 'candidate claims must be reproducible'))
    return out
async def worker(i):
    role=roles[(i-1)%len(roles)]
    return i,role,analyze(i,role)
async def main():
    results=await asyncio.gather(*(worker(i) for i in range(1,701)))
    raw=[]
    for i,r,fs in results:
        raw += [(i,r,*f) for f in fs]
    candidates=[x for x in raw if x[2]=='unvalidated identifier']
    for i,r,h,e in candidates:
        conn.execute('insert into findings(agent,hypothesis,evidence,status) values(?,?,?,?)',(f'agent-{i:03d}',h,e,'candidate'))
    conn.commit()
    print(json.dumps({'workers':700,'raw_observations':len(raw),'candidate_findings':len(candidates),'confirmed_findings':0,'external_network':0,'host_access':0},indent=2))
    print('All candidate claims require reproduction; none confirmed.')
asyncio.run(main())
