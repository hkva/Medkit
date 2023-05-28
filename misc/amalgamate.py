#!/usr/bin/env python3

import re

SRCFILE='medkit.h'
DSTFILE='medkit-amalgamated.h'

def build_file(lines):
    out = []
    for line in lines:
        m = re.search(r'@amalgamate-remove', line)
        if m:
            continue
        m = re.search(r'@amalgamate-include-comment\(\"(.*)\"\)', line)
        if m:
            with open(m[1], 'r') as f:
                out += [ f'// {fl}' for fl in f.readlines() ]
            continue
        m = re.search(r'@amalgamate-include\(\"(.*)\"\)', line)
        if m:
            with open(m[1], 'r') as f:
                out += build_file(f.readlines())
            continue
        out.append(line)
    return out

if __name__ == '__main__':
    with open(SRCFILE, 'r') as src:
        with open(DSTFILE, 'w') as out:
            out.writelines(build_file(src.readlines()))
