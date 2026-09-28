import glob
import re

for filepath in glob.glob("frontend/src/**/*.tsx", recursive=True):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    new_content = re.sub(r'#(334155|475569|64748b)', 'var(--color-text-muted)', content)
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {filepath}")
