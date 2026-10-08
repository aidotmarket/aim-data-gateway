#!/usr/bin/env python3
"""Read-only backend model conformance runner. No backend files are written.

Usage: python run_python.py BACKEND_CHECKOUT [--generate]
Run --generate before the Go test, then run again to compare results.
"""
import argparse
import base64
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
sys.dont_write_bytecode = True

OUT = pathlib.Path('/Users/max/koskadeux-state/s1791/cp81/conformance')
def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
def digest(value):
    return hashlib.sha256(canon(value)).hexdigest()
def save(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/name).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('backend')
    p.add_argument('--generate', action='store_true')
    args = p.parse_args()
    sys.path.insert(0, str(pathlib.Path(args.backend).resolve()))
    from app.schemas.data_verification import SuccessfulVerificationReport, TerminalVerificationReport, QuoteProbeRequest, SignedScanSpec
    from app.schemas.verification_runner import RunnerRegistration, ProbeReceipt
    from services.gateway_signer.verification_contract import GatewayScanPayload, canonical_json_bytes
    models = dict(scan_spec=GatewayScanPayload, scan_report=SuccessfulVerificationReport,
                  terminal_report=TerminalVerificationReport, probe_report=ProbeReceipt,
                  quote_probe=QuoteProbeRequest, registration=RunnerRegistration)
    schemas = {k: m.model_json_schema() for k, m in models.items()}
    # SignedScanSpec is the retired RSA wrapper, not the S1791 Ed25519 envelope.
    save('schema-digests.json', {**{k: {'model': models[k].__module__+'.'+models[k].__name__, 'sha256': digest(s)} for k,s in schemas.items()},
                               'legacy_signed_scan_spec': {'model': 'SignedScanSpec', 'sha256': digest(SignedScanSpec.model_json_schema())}})
    sha = subprocess.check_output(['rtk','proxy','git','-C',args.backend,'rev-parse','HEAD'], text=True).strip()
    if args.generate:
        root = pathlib.Path(__file__).resolve().parents[2]/'contract/vectors/verification'
        if not root.exists():
            root = pathlib.Path.cwd()/'contract/vectors/verification'
        vectors = {k: json.loads((root/(k+'.json')).read_text())['input'] for k in ['scan_spec','scan_report','terminal_report','probe_report','registration']}
        vectors['scan_spec'] = json.loads(base64.urlsafe_b64decode(vectors['scan_spec']['payload_b64']+'=='))
        vectors['quote_probe'] = vectors['probe_report']['probe']
        cases = []
        coverage = []
        for cls, baseline in vectors.items():
            schema = schemas[cls]
            cases.append(dict(id=cls+'/baseline', cls=cls, input=baseline, dimension='baseline'))
            def resolve(s):
                if '$ref' in s: return schema['$defs'][s['$ref'].split('/')[-1]]
                return s
            def visit(value, s, path):
                s=resolve(s)
                if isinstance(value, dict):
                    for field, child in value.items():
                        cs=resolve(s.get('properties',{}).get(field,{}))
                        cp=path+[field]
                        variants=[('positive',child),('requiredness', '__DELETE__'),('null',None)]
                        for name, val in [('string','invalid'),('integer',-1),('float',1.0),('boolean',True),('false',False),('array',[]),('object',{})]:
                            variants.append(('type_'+name,val))
                        for lit in cs.get('enum', [cs['const']] if 'const' in cs else []):
                            variants.append(('literal_'+str(lit),lit))
                        for bound in ['minimum','maximum','exclusiveMinimum','exclusiveMaximum']:
                            if bound in cs:
                                b=cs[bound]
                                variants.extend([(bound+'_at',b),(bound+'_below',b-1),(bound+'_above',b+1)])
                        for bound in ['minLength','maxLength']:
                            if bound in cs:
                                b=cs[bound]
                                for n in sorted(set([max(0,b-1),b,b+1])):
                                    variants.append((bound+'_'+str(n),'x'*n))
                        if isinstance(child,list):
                            item_schema=resolve(cs.get('items',{}))
                            literals=item_schema.get('enum',[item_schema['const']] if 'const' in item_schema else [])
                            for lit in literals:
                                variants.append(('item_literal_'+str(lit),[lit]))
                            variants.append(('item_literal_invalid',['invalid']))
                            for bound in ['minItems','maxItems']:
                                if bound in cs:
                                    b=cs[bound]
                                    for n in sorted(set([max(0,b-1),b,b+1])):
                                        variants.append((bound+'_'+str(n),[child[0] if child else 'invalid']*n))
                        coverage.append(dict(cls=cls,path=cp,schema=cs,dimensions=['positive','requiredness','null','type','literal/bounds when declared']))
                        for name, replacement in variants:
                            v=copy.deepcopy(baseline); dest=v
                            for part in path: dest=dest[part]
                            if replacement == '__DELETE__': dest.pop(field)
                            else: dest[field]=replacement
                            cases.append(dict(id=cls+'/'+'/'.join(map(str,cp))+'/'+name,cls=cls,input=v,dimension=name))
                        visit(child,cs,cp)
                elif isinstance(value,list):
                    for i, child in enumerate(value): visit(child,s.get('items',{}),path+[i])
            visit(baseline,schema,[])
        save('corpus.json',dict(authority='5d8267dc',gateway_base='7fcbd770c7ffb7e21284e28767eeafedfe878c23',backend_actual=sha,cases=cases,coverage=coverage))
    corpus=json.loads((OUT/'corpus.json').read_text())
    results=[]
    for case in corpus['cases']:
        r=dict(id=case['id'],accept=False)
        try:
            model=models[case['cls']].model_validate(case['input'])
            output=canonical_json_bytes(model.model_dump(mode='json'))
            r.update(accept=True,sha256=hashlib.sha256(output).hexdigest())
        except Exception as e:
            r['error']=str(e)
        results.append(r)
    save('python-results.json',dict(backend_actual=sha,backend_requested='4d6875de',authority='5d8267dc',results=results))
    if (OUT/'go-results.json').exists() and not args.generate:
        go={r['id']:r for r in json.loads((OUT/'go-results.json').read_text())['results']}
        if set(go) != {r['id'] for r in results}:
            raise RuntimeError('Go results do not cover exactly this corpus; rerun Go after generation')
        differences=[]
        for r in results:
            g=go.get(r['id'])
            if g is None or g['accept'] != r['accept'] or (r['accept'] and g.get('sha256') != r.get('sha256')):
                differences.append(dict(id=r['id'],go=g,python=r))
        save('diff.json',dict(authority='5d8267dc',backend_actual=sha,backend_requested='4d6875de',cases=len(results),differences=differences,zero_diff=not differences))
        print(f'{len(results)} cases; {len(differences)} divergences; backend {sha}')
    else: print(f'{len(results)} Python cases; backend {sha}; run Go then rerun Python')

if __name__ == '__main__': main()
