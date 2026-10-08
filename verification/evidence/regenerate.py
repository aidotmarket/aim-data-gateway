#!/usr/bin/env python3
"""One invocation creates a fresh CP81 generation; refuses moved main/RCs.

Usage: rtk proxy python3 verification/evidence/regenerate.py
Durable command logs are complete, without terminal-output truncation.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
ROOT = Path('/Users/max/koskadeux-state/s1791/cp81/gen2')
BACKEND = '/var/tmp/cp81-backend-0f7b61ff'
PYTHON = '/Users/max/Projects/ai-market/ai-market-backend/.venv-ci/bin/python'
GATEWAY_SHA = '25779953b1c27e0dec5f39ba871422a6b81f8cff'
BACKEND_SHA = '0f7b61ff58463a1bd1fe40f89d824059d1bb2bc3'

def main():
    ROOT.mkdir(parents=True, exist_ok=False)
    (ROOT/'logs').mkdir()
    commands = []
    env = {**os.environ, 'EVIDENCE_OUT': str(ROOT/'captures'), 'PYTHONDONTWRITEBYTECODE': '1'}
    def command(argv):
        argv = ['rtk', 'proxy', *argv]
        log = ROOT/'logs'/f'{len(commands)+1:02d}.log'
        with log.open('wb') as output:
            proc = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, env=env)
        commands.append(dict(argv=argv, cwd=str(Path.cwd()), environment={'EVIDENCE_OUT': env['EVIDENCE_OUT'], 'PYTHONDONTWRITEBYTECODE': '1'}, exit_code=proc.returncode, log=str(log.relative_to(ROOT))))
        (ROOT/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        print(f'{proc.returncode}: {" ".join(argv)} (full log: {log})', flush=True)
        if proc.returncode:
            raise RuntimeError(f'command failed; evidence preserved: {log}')
        return log.read_text()
    command(['git', 'fetch', 'origin', 'main'])
    assert command(['git', 'rev-parse', 'origin/main']).strip() == GATEWAY_SHA, 'REFUSE: origin/main moved'
    evidence_commit = command(['git', 'rev-parse', 'HEAD']).strip()
    # Evidence commits must descend directly from the required final gateway RC.
    command(['git', 'merge-base', '--is-ancestor', GATEWAY_SHA, 'HEAD'])
    paths = command(['git', 'diff', '--name-only', GATEWAY_SHA, 'HEAD']).splitlines()
    assert all(p.startswith('verification/evidence/') for p in paths), 'production changes refused'
    assert not command(['git', 'status', '--porcelain']).strip(), 'commit harness before generating'
    assert command(['git', '-C', BACKEND, 'rev-parse', 'HEAD']).strip() == BACKEND_SHA
    assert not command(['git', '-C', BACKEND, 'status', '--porcelain']).strip(), 'backend not clean'
    provenance = dict(gateway_sha=GATEWAY_SHA, backend_sha=BACKEND_SHA, evidence_commit=evidence_commit,
                      backend_worktree=BACKEND, generation='gen2', captures_generated_once=True)
    (ROOT/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
    scripts = ROOT/'harness'
    shutil.copytree('verification/evidence', scripts)
    command([PYTHON, '-B', 'verification/evidence/run_python.py', BACKEND, '--generate'])
    command(['go', 'test', '-count=1', '-tags', 'evidence', './verification/evidence/...', '-v'])
    command([PYTHON, '-B', 'verification/evidence/run_python.py', BACKEND])
    command([PYTHON, '-B', 'verification/evidence/run_python.py', BACKEND, '--directional'])
    command([PYTHON, '-B', 'verification/evidence/raw_locator.py', BACKEND, str(ROOT/'tamper/raw_locator')])
    command(['go', 'vet', '-tags', 'evidence', './...'])
    command(['go', 'vet', './...'])
    command(['git', 'diff', '--check'])
    assert not command(['git', '-C', BACKEND, 'status', '--porcelain']).strip()
    command(['git', 'fetch', 'origin', 'main'])
    assert command(['git', 'rev-parse', 'origin/main']).strip() == GATEWAY_SHA, 'REFUSE: main moved during generation'
    command([sys.executable, '-B', 'verification/evidence/generation_manifest.py', str(ROOT)])
    # The manifest write is internal to this invocation; all external commands,
    # including the independent self-check, have already completed and are logged.
    from generation_manifest import check, digest
    frames = check(ROOT)
    inventory = {str(p.relative_to(ROOT)): dict(sha256=digest(p), bytes=p.stat().st_size)
                 for p in sorted(ROOT.rglob('*')) if p.is_file()}
    manifest = dict(**provenance, artifacts=inventory, frame_sha256=frames, commands=commands,
                    self_check=dict(passed=True, capture_frames=len(frames), sources=['captures', 'keyflow/absence.json', 'reconstruction/results.json', 'conformance/directional.json']),
                    checksum_policy='manifest.json is hashed separately by manifest.sha256; neither lists its own recursive digest.')
    (ROOT/'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    (ROOT/'manifest.sha256').write_text(digest(ROOT/'manifest.json')+'  manifest.json\n')
    print(f'Generation complete: {ROOT}/manifest.json')

if __name__ == '__main__':
    main()
