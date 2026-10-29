#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Use the immutable HTTP tooling dependency without introducing local package dependencies."""
from pathlib import Path
import argparse,re,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out-dir',type=Path,required=True);p.add_argument('--receipts',type=Path);a=p.parse_args();out=a.out_dir.resolve()
    if out.exists() or ROOT in out.parents:p.error('new external output required')
    text=(ROOT/'package.yaml').read_text();m=re.search(r'^  http:\n    git: (\S+)\n    rev: ([0-9a-f]{40})\s*$',text,re.M)
    if not m:raise ValueError('HTTP must use an immutable public Git dependency')
    bootstrap=out.parent/(out.name+'-http-tooling')
    if bootstrap.exists():raise ValueError('new tooling directory required')
    for cmd in [['git','init',str(bootstrap)],['git','-C',str(bootstrap),'config','core.autocrlf','false'],['git','-C',str(bootstrap),'remote','add','origin',m[1]],['git','-C',str(bootstrap),'fetch','--depth','1','origin',m[2]],['git','-C',str(bootstrap),'checkout','--detach','FETCH_HEAD']]:subprocess.run(cmd,check=True)
    if a.receipts:cmd=[sys.executable,str(bootstrap/'scripts/release_source.py'),'--package-root',str(ROOT),'--receipts',str(a.receipts.resolve()),'--out-dir',str(out)]
    else:cmd=[sys.executable,str(bootstrap/'scripts/ci.py'),'--adapter-root',str(ROOT),'--out-dir',str(out)]
    subprocess.run(cmd,check=True)
if __name__=='__main__':main()
