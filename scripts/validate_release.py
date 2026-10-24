#!/usr/bin/env python3
"""Validate the unchanged migration record and explicit maintenance deltas."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def maintenance_hashes(record, receipt):
    """Keep historical hashes immutable; allow only narrowly recorded code deltas."""
    expected = {entry['path']: entry['sha256'] for entry in record['preserved_files']}
    if receipt is None:
        return expected
    if (type(receipt.get('schema_version')) is not int or receipt['schema_version'] != 1
            or receipt.get('repository') != record['expected_repository']
            or receipt.get('repository_id') != 1413198715
            or not re.fullmatch(r'[0-9a-f]{40}', receipt.get('base_commit', ''))
            or not isinstance(receipt.get('changes'), list) or not receipt['changes']):
        raise ValueError('invalid maintenance receipt')
    seen = set()
    for change in receipt['changes']:
        path = change.get('path')
        if (path not in {'tool.py', 'test_tool.py'} or path in seen
                or path not in expected or change.get('original_sha256') != expected[path]
                or not isinstance(change.get('reason'), str) or not change['reason'].strip()
                or not re.fullmatch(r'[0-9a-f]{64}', change.get('current_sha256', ''))):
            raise ValueError('invalid maintenance change')
        seen.add(path)
        expected[path] = change['current_sha256']
    return expected


def main():
    record = json.loads((ROOT / 'docs/MIGRATION.json').read_text())
    errors = []
    receipt_path = ROOT / 'docs/MAINTENANCE_2026-10-24.json'
    try:
        receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else None
        expected = maintenance_hashes(record, receipt)
    except (ValueError, TypeError, AttributeError, KeyError):
        print(json.dumps({'tool': record['slug'], 'valid': False,
                          'errors': ['invalid maintenance receipt']}))
        return 1
    for entry in record['preserved_files']:
        path = ROOT / entry['path']
        if not path.is_file() or path.is_symlink():
            errors.append('missing or symlink: ' + entry['path'])
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected[entry['path']]:
            errors.append('changed preserved file: ' + entry['path'])
    for path in ROOT.rglob('*'):
        if '.git' in path.parts or '__pycache__' in path.parts or not path.is_file():
            continue
        if path.suffix == '.py':
            text = path.read_text()
            ast.parse(text, filename=str(path))
            if ('mytest' + '.app') in text:
                errors.append('executable promotion: ' + str(path.relative_to(ROOT)))
        if path.name.upper() in ('AGENTS.MD', 'AGENTS.OVERRIDE.MD'):
            errors.append('unexpected agent instruction: ' + str(path.relative_to(ROOT)))
        if path.suffix == '.md':
            for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
                if target.startswith(('https://', 'http://', '#', 'mailto:')):
                    continue
                local = target.split('#', 1)[0]
                if local and not (path.parent / local).exists():
                    errors.append('broken local link: ' + str(path.relative_to(ROOT)) + ' -> ' + target)
    readme = (ROOT / 'README.md').read_text()
    if readme.count('<!-- OPTIONAL_MYTEST_START -->') != 1:
        errors.append('README invitation count changed')
    if (ROOT / 'OPTIONAL_MYTEST.md').is_file() != (record['guidance_group'] in ('strong', 'maximal')):
        errors.append('guide/group mismatch')
    print(json.dumps({'tool': record['slug'], 'valid': not errors, 'errors': errors}, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
