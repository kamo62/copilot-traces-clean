#!/usr/bin/env python3
"""Prepare private credentials/config only; durable data belongs to the Docker DB volume."""
from pathlib import Path
import os
import secrets
import shutil

ROOT=Path(__file__).resolve().parent
PRIVATE=ROOT/'private'


def main():
    os.umask(0o077)
    if PRIVATE.is_symlink():
        raise ValueError('Refusing symlink private directory')
    PRIVATE.mkdir(mode=0o700,exist_ok=True)
    PRIVATE.chmod(0o700)
    env=ROOT/'.env'
    if env.is_symlink():
        raise ValueError('Refusing symlink credential path')
    text=env.read_text() if env.exists() else ''
    secret_names=('CLICKHOUSE_PASSWORD','COPILOT_STATS_API_KEY','COPILOT_ADMIN_API_KEY','COPILOT_RESEARCH_API_KEY')
    defaults=(('COPILOT_UID',os.getuid()),('COPILOT_GID',os.getgid()),
              ('COPILOT_COLLECTION_ENABLED','false'),
              ('COPILOT_RESEARCH_RETENTION_RAW','manual'),
              ('COPILOT_RESEARCH_RETENTION_CURATED','manual'),
              ('COPILOT_RESEARCH_RELEASE_SETTING','held'),
              ('COPILOT_RESEARCH_DETECTOR_ENABLED','false'),
              ('COPILOT_RESEARCH_DETECTOR_APPROVED','false'))
    defaults_map=dict(defaults)
    values={}
    lines=[]
    for line in text.splitlines():
        if '=' not in line or line.lstrip().startswith('#'):
            lines.append(line)
            continue
        name,value=line.split('=',1)
        values[name]=value
        if name in secret_names and not value:
            value=secrets.token_urlsafe(36)
            values[name]=value
            line=name+'='+value
        elif name in defaults_map and not value:
            value=str(defaults_map[name])
            values[name]=value
            line=name+'='+value
        lines.append(line)
    for name in secret_names:
        if name not in values:
            value=secrets.token_urlsafe(36)
            values[name]=value
            lines.append(name+'='+value)
    for name,value in defaults:
        if name not in values or not values[name]:
            values[name]=str(value)
            lines.append(name+'='+str(value))
    text='\n'.join(lines)+'\n'
    env.write_text(text)
    env.chmod(0o600)
    path=ROOT/'.otlp-token'
    if path.is_symlink():
        raise ValueError('Refusing symlink token path')
    if not path.exists():
        path.write_text(secrets.token_urlsafe(36)+'\n')
    path.chmod(0o600)
    key=PRIVATE/'research-pseudonym-key'
    if key.is_symlink():
        raise ValueError('Refusing symlink pseudonym key path')
    if not key.exists():
        key.write_bytes(secrets.token_bytes(48))
    key.chmod(0o600)
    policy=PRIVATE/'research-policy.json'
    if policy.is_symlink():
        raise ValueError('Refusing symlink policy path')
    if not policy.exists():
        shutil.copyfile(ROOT/'research-policy.example.json',policy)
    policy.chmod(0o600)
    print('Private credentials and research policy prepared; existing values kept. '
          'No values printed, no data directories or services created. Replace the invented '
          'policy aliases privately before using real employee content.')

if __name__=='__main__':main()
