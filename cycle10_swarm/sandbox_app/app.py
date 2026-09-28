from pathlib import Path
import json

BASE = Path(__file__).parent
DATA = BASE / 'data'
ALLOWED_USERS = {'u1', 'u2'}


def load_profile(user_id: str):
    if user_id not in ALLOWED_USERS:
        return None
    p = DATA / f'{user_id}.json'
    if p.parent != DATA or not p.exists():
        return None
    return json.loads(p.read_text())


def format_profile(profile):
    if not profile:
        return {'error': 'not found'}
    return {'id': profile['id'], 'name': profile['name'], 'role': profile['role']}
