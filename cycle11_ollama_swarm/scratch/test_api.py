import urllib.request
import json
import time

payload = {
    "repo": "C:/Users/Lenovo/Documents/cycle10_swarm_harness/backend",
    "model": "groq/llama-3.1-8b-instant",
    "challenger_model": "groq/llama-3.1-8b-instant",
    "no_sast": True
}
data = json.dumps(payload).encode('utf-8')

req = urllib.request.Request('http://127.0.0.1:8000/api/repo-scan', 
    data=data,
    headers={'Content-Type': 'application/json'})

try:
    resp = urllib.request.urlopen(req)
    run_id = json.loads(resp.read())['run_id']
    req_stream = urllib.request.Request(f'http://127.0.0.1:8000/api/scan/{run_id}/stream')
    resp_stream = urllib.request.urlopen(req_stream)
    print('Stream connected for run', run_id)
    for line in resp_stream:
        s = line.decode().strip()
        if not s: continue
        print(s)
        if 'real-world scan finished' in s.lower() or 'error' in s.lower():
            break
except Exception as e:
    print('Exception:', e)
