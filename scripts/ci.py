#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Use the immutable HTTP tooling dependency without introducing local package dependencies."""
from pathlib import Path
import argparse,json,re,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out-dir',type=Path,required=True);p.add_argument('--sdk',type=Path);p.add_argument('--openssl-root',type=Path);p.add_argument('--receipts',type=Path);a=p.parse_args();out=a.out_dir.resolve()
    if out.exists() or ROOT in out.parents:p.error('new external output required')
    text=(ROOT/'package.yaml').read_text();m=re.search(r'^  http:\n    git: (\S+)\n    rev: ([0-9a-f]{40})\s*$',text,re.M)
    if not m:raise ValueError('HTTP must use an immutable public Git dependency')
    url,ref=m.groups()
    tools=json.loads((ROOT/'release.lock.json').read_text()).get('ci_tooling')
    if tools:
        if tools.get('url')!=url or not re.fullmatch('[0-9a-f]{40}',tools.get('commit','')):
            raise ValueError('CI tooling must be immutable and use the declared HTTP origin')
        ref=tools['commit']
    bootstrap=out.parent/(out.name+'-http-tooling')
    if bootstrap.exists():raise ValueError('new tooling directory required')
    for cmd in [['git','init',str(bootstrap)],['git','-C',str(bootstrap),'config','core.autocrlf','false'],['git','-C',str(bootstrap),'remote','add','origin',url],['git','-C',str(bootstrap),'fetch','--depth','1','origin',ref],['git','-C',str(bootstrap),'checkout','--detach','FETCH_HEAD']]:subprocess.run(cmd,check=True)
    if a.receipts:cmd=[sys.executable,str(bootstrap/'scripts/release_source.py'),'--package-root',str(ROOT),'--receipts',str(a.receipts.resolve()),'--out-dir',str(out)]
    else:cmd=[sys.executable,str(bootstrap/'scripts/ci.py'),'--adapter-root',str(ROOT),'--out-dir',str(out)]
    if a.sdk and not a.receipts:cmd+=['--sdk',str(a.sdk.resolve())]
    if a.openssl_root and not a.receipts:cmd+=['--openssl-root',str(a.openssl_root.resolve())]
    subprocess.run(cmd,check=True)
if __name__=='__main__':main()
