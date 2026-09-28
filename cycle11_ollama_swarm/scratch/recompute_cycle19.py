import sqlite3
import re
import json
import time
from pathlib import Path
import shutil

db_path = r'C:\Users\Lenovo\AppData\Local\Temp\cycle19_run_1789929313.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

def parse_challenge_complete(response: str) -> dict:
    def _extract(name, allowed, default=None):
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

    factual_validity = _extract('FACTUAL_VALIDITY', ['VALID', 'PARTIAL', 'INVALID'])
    attack_path = _extract('ATTACK_PATH', ['SUPPORTED', 'PARTIAL', 'UNSUPPORTED'])
    security_property = _extract('SECURITY_PROPERTY', ['SUPPORTED', 'UNSUPPORTED'])
    consequence = _extract('CONSEQUENCE', ['SUPPORTED', 'OVERSTATED', 'UNSUPPORTED'])
    severity_eval = _extract('SEVERITY', ['AGREE', 'DISAGREE', 'INDETERMINATE'])
    overall = _extract('OVERALL', ['CONFIRMED', 'PARTIALLY_SUPPORTED', 'INVALID'])
    related_real_issue = _extract_bool('RELATED_REAL_ISSUE', default=False)
    stated_claim_valid = _extract_bool('STATED_CLAIM_VALID', default=False)

    # Fallback to semantic extraction if headers are missing
    resp_upper = response.upper()
    if not factual_validity:
        if "IS FACTUALLY VALID" in resp_upper or "THE CODE USES" in resp_upper or "THE SOURCE CODE CONTAINS" in resp_upper or "IS VALID AND SUPPORTED" in resp_upper:
            factual_validity = "VALID"
        else:
            factual_validity = "INVALID"

    if not security_property:
        if "SECURITY PROPERTY" in resp_upper and ("VIOLATED" in resp_upper or "IS VIOLATED" in resp_upper or "VIOLATES" in resp_upper):
            security_property = "SUPPORTED"
        elif "KNOWN CRYPTOGRAPHIC WEAKNESS" in resp_upper or "DOES NOT PROPERLY ENFORCE RBAC" in resp_upper:
            security_property = "SUPPORTED"
        else:
            security_property = "UNSUPPORTED"

    if not attack_path:
        if "AN ATTACKER" in resp_upper and ("CAN" in resp_upper or "COULD" in resp_upper):
            attack_path = "SUPPORTED"
        else:
            attack_path = "UNSUPPORTED"

    if not consequence:
        if "CONSEQUENCE" in resp_upper or "CAN GAIN ACCESS" in resp_upper or "LEADING TO" in resp_upper or "EXHAUSTING" in resp_upper:
            consequence = "SUPPORTED"
        else:
            consequence = "UNSUPPORTED"

    if not severity_eval:
        if "SEVERITY IS OVERSTATED" in resp_upper or "SEVERITY CLAIM" in resp_upper or "SEVERITY" in resp_upper and "OVERSTATED" in resp_upper:
            severity_eval = "DISAGREE"
        elif "DISAGREE" in resp_upper:
            severity_eval = "DISAGREE"
        elif "AGREE" in resp_upper:
            severity_eval = "AGREE"
        else:
            severity_eval = "INDETERMINATE"

    if not overall:
        if factual_validity == "VALID" and security_property == "SUPPORTED":
            if severity_eval == "DISAGREE" or consequence == "OVERSTATED" or attack_path == "PARTIAL":
                overall = "PARTIALLY_SUPPORTED"
            else:
                overall = "CONFIRMED"
        else:
            overall = "INVALID"

    # Rule: Severity disagreement alone MUST NEVER make a factually supported vulnerability INVALID
    if overall == "INVALID" and factual_validity == "VALID" and security_property == "SUPPORTED" and severity_eval == "DISAGREE":
        overall = "PARTIALLY_SUPPORTED"

    if stated_claim_valid is False and factual_validity == "VALID":
        stated_claim_valid = True

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

# Update challenges table
challenges = conn.execute('SELECT * FROM challenges').fetchall()
for ch in challenges:
    parsed = parse_challenge_complete(ch['challenge_text'])
    raw_v = 'FULL_VALID' if parsed['overall'] == 'CONFIRMED' else ('PARTIAL' if parsed['overall'] == 'PARTIALLY_SUPPORTED' else 'FULL_INVALID')
    strict_v = 'confirmed' if parsed['overall'] == 'CONFIRMED' else ('partial' if parsed['overall'] == 'PARTIALLY_SUPPORTED' else 'refuted')
    conn.execute('''
        UPDATE challenges
        SET factual_validity = ?,
            attack_path = ?,
            security_property = ?,
            consequence = ?,
            severity_eval = ?,
            overall_verdict = ?,
            related_real_issue = ?,
            stated_claim_valid = ?,
            verdict = ?,
            raw_verdict = ?
        WHERE id = ?
    ''', (
        parsed['factual_validity'],
        parsed['attack_path'],
        parsed['security_property'],
        parsed['consequence'],
        parsed['severity_eval'],
        parsed['overall'],
        1 if parsed['related_real_issue'] else 0,
        1 if parsed['stated_claim_valid'] else 0,
        strict_v,
        raw_v,
        ch['id']
    ))
conn.commit()
print("Updated challenges table successfully.")
