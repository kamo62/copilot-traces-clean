#!/usr/bin/env python3
"""Fail before deployment unless Linux Docker named volumes are on non-rotating storage."""
import json
from pathlib import Path
import subprocess

def main():
    root=Path(subprocess.check_output(['docker','info','--format','{{.DockerRootDir}}'],text=True).strip())
    mounts=json.loads(subprocess.check_output(['findmnt','--json','--target',str(root),'--output','SOURCE,TARGET'],text=True))
    source=mounts['filesystems'][0]['source'].split('[',1)[0]
    rotating=subprocess.check_output(['lsblk','-dn','-o','ROTA',source],text=True).strip()
    if rotating!='0':raise SystemExit('Docker root is not verified on SSD/non-rotating storage; configure it before starting.')
    print(json.dumps({'docker_root':str(root),'device':source,'rotating':False,'named_volumes_on_ssd':True}))

if __name__=='__main__':main()
