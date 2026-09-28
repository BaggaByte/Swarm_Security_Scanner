import sqlite3
import re
import json

db_path = r'C:\Users\Lenovo\AppData\Local\Temp\cycle19_run_1789929313.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

def parse_robust(response):
    def _extract(name, allowed, default=None):
        # matches **NAME:** VAL or **NAME**: VAL or NAME: VAL or 1. NAME: VAL
        pattern = rf'(?:(?:\d+\.|\*|-)?\s*\**{name}(?:\:|\=)?\**\s*[:=]?\s*\**([A-Za-z_]+))'
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            val = m.group(1).upper()
            for a in allowed:
                if val == a or val.startswith(a):
                    return a
        return default

    def _extract_bool(name, default=False):
        pattern = rf'(?:(?:\d+\.|\*|-)?\s*\**{name}(?:\:|\=)?\**\s*[:=]?\s*\**([A-Za-z_]+))'
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            val = m.group(1).upper()
            if 'TRUE' in val or 'YES' in val or '1' in val:
                return True
            if 'FALSE' in val or 'NO' in val or '0' in val:
                return False
        return default

    factual_validity = _extract('FACTUAL_VALIDITY', ['VALID', 'PARTIAL', 'INVALID'], default='INVALID')
    attack_path = _extract('ATTACK_PATH', ['SUPPORTED', 'PARTIAL', 'UNSUPPORTED'], default='UNSUPPORTED')
    security_property = _extract('SECURITY_PROPERTY', ['SUPPORTED', 'UNSUPPORTED'], default='UNSUPPORTED')
    consequence = _extract('CONSEQUENCE', ['SUPPORTED', 'OVERSTATED', 'UNSUPPORTED'], default='UNSUPPORTED')
    severity_eval = _extract('SEVERITY', ['AGREE', 'DISAGREE', 'INDETERMINATE'], default='INDETERMINATE')
    overall = _extract('OVERALL', ['CONFIRMED', 'PARTIALLY_SUPPORTED', 'INVALID'], default=None)
    related_real_issue = _extract_bool('RELATED_REAL_ISSUE', default=False)
    stated_claim_valid = _extract_bool('STATED_CLAIM_VALID', default=False)

    if not overall:
        if factual_validity == 'VALID' and attack_path == 'SUPPORTED' and security_property == 'SUPPORTED':
            overall = 'CONFIRMED'
        elif factual_validity in ('VALID', 'PARTIAL') and (security_property == 'SUPPORTED' or related_real_issue):
            overall = 'PARTIALLY_SUPPORTED'
        else:
            overall = 'INVALID'

    if overall == 'INVALID' and factual_validity == 'VALID' and security_property == 'SUPPORTED' and severity_eval == 'DISAGREE':
        if attack_path == 'SUPPORTED' and consequence in ('SUPPORTED', 'OVERSTATED'):
            overall = 'CONFIRMED'
        else:
            overall = 'PARTIALLY_SUPPORTED'

    return {
        'factual_validity': factual_validity,
        'attack_path': attack_path,
        'security_property': security_property,
        'consequence': consequence,
        'severity_eval': severity_eval,
        'overall': overall,
        'related_real_issue': related_real_issue,
        'stated_claim_valid': stated_claim_valid
    }

rows = conn.execute('SELECT * FROM challenges ORDER BY finding_id, challenger_id').fetchall()
for r in rows:
    p = parse_robust(r['challenge_text'])
    print(f"Finding #{r['finding_id']:02d} ({r['challenger_id']}): Factual={p['factual_validity']} | Path={p['attack_path']} | Prop={p['security_property']} | Cons={p['consequence']} | Sev={p['severity_eval']} | Overall={p['overall']} | Related={p['related_real_issue']} | StatedValid={p['stated_claim_valid']}")
