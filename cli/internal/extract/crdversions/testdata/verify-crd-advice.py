#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Reproduces crd-advice-verification.json.

Usage: python3 -I verify-crd-advice.py <rules.json> <scratch-dir> <out.json>

For every crd-version-removal rule in the pack, fetches each cited file at the
cited revision (shallow git fetch from the public upstream repository), checks
that the sha256 of the whole file equals the cited contentDigest, and records
spec.versions[] (name, served, storage) of that file. The replacement version
is the highest served version of the later CRD (the source whose id does not
start with "crd-versions-"), ranked as the extractor ranks versions; a stored
version is present when a version the later CRD no longer serves has
storage: true in the earlier or the later file. Needs git and PyYAML.
"""
import hashlib, json, os, re, subprocess, sys
import yaml

KUBE = re.compile(r'^v([0-9]+)(?:(alpha|beta)([0-9]+))?$')

def rank(n):
    m = KUBE.match(n)
    if not m:
        return (0, 0, 0)
    return ({'alpha': 0, 'beta': 1}.get(m.group(2), 2), int(m.group(1)), int(m.group(3) or 0))

def higher(a, b):
    return (rank(a), a) > (rank(b), b)

def fetch(work, repo, rev, path):
    d = os.path.join(work, re.sub(r'\W', '_', repo) + '_' + rev)
    if not os.path.isdir(d):
        os.makedirs(d)
        for c in (['init', '-q'], ['remote', 'add', 'o', repo + '.git'], ['fetch', '-q', '--depth=1', 'o', rev]):
            subprocess.run(['git', '-C', d] + c, check=True)
    return subprocess.run(['git', '-C', d, 'show', 'FETCH_HEAD:' + path], check=True, capture_output=True).stdout

def main(rules, work, out):
    pack = json.load(open(rules))
    res = []
    for e in pack['entries']:
        r = e['rule']
        if '.crd-version-removal.' not in r['id']:
            continue
        srcs = []
        for s in r['evidence']['sources']:
            url = s['url']
            repo, rest = url.split('/blob/', 1)
            rev, path = rest.split('/', 1)
            assert rev == s['revision'], r['id']
            raw = fetch(work, repo, rev, path)
            dg = 'sha256:' + hashlib.sha256(raw).hexdigest()
            if dg != s['contentDigest']:
                sys.exit('%s %s: digest %s != cited %s' % (r['id'], s['id'], dg, s['contentDigest']))
            doc = yaml.safe_load(raw)
            vs = [{'name': v['name'], 'served': bool(v.get('served')), 'storage': bool(v.get('storage'))} for v in doc['spec']['versions']]
            srcs.append({'id': s['id'], 'repo': repo, 'revision': rev, 'path': path, 'digest': dg, 'versions': vs})
        srcs.sort(key=lambda x: x['id'])
        later = [s for s in srcs if not s['id'].startswith('crd-versions-')]
        earlier = [s for s in srcs if s['id'].startswith('crd-versions-')]
        assert len(later) == 1 and len(earlier) == 1, r['id']
        served_later = {v['name'] for v in later[0]['versions'] if v['served']}
        served_earlier = {v['name'] for v in earlier[0]['versions'] if v['served']}
        removed = sorted(served_earlier - served_later)
        repl = ''
        for n in sorted(served_later):
            if repl == '' or higher(n, repl):
                repl = n
        stored = any(v['storage'] and v['name'] in removed for s in srcs for v in s['versions'])
        res.append({'ruleId': r['id'], 'sources': srcs, 'removedVersions': removed,
                    'replacement': repl, 'storedVersionsPresent': stored})
    res.sort(key=lambda x: x['ruleId'])
    json.dump({'version': 1, 'rules': res}, open(out, 'w'), indent=1)
    open(out, 'a').write('\n')

if __name__ == '__main__':
    main(*sys.argv[1:4])
