"""Extend the pinned corpus using unchanged, git-extracted reference modules."""
import sys, types, importlib.util, hashlib, json, argparse
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
parser=argparse.ArgumentParser()
parser.add_argument('--connector', required=True)
parser.add_argument('--signer', required=True)
args=parser.parse_args()
# Import-only placeholder: scan_bytes never calls the unused JWT dependency.
sys.modules.setdefault('jwt', types.ModuleType('jwt'))
spec=importlib.util.spec_from_file_location('app.services.marketplace_action_signer',args.signer);signer=importlib.util.module_from_spec(spec);sys.modules[spec.name]=signer;spec.loader.exec_module(signer)
spec=importlib.util.spec_from_file_location('oracle',args.connector);oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
root=Path('verification/testdata/oracle'); manifest=json.loads((root/'manifest.json').read_bytes())
assert pa.__version__ == manifest['pyarrow_version']
# The legacy runtime (aim-data Dockerfile python:3.11, requirements pandas==2.1.4)
# has pandas, which changes how Arrow hands sub-microsecond timestamps to Python.
import pandas
assert sys.version_info[:2] == (3, 11) and pandas.__version__ == '2.1.4'
assert hashlib.sha256(Path(args.connector).read_bytes()).hexdigest()==manifest['connector_sha256']
kwargs=dict(commitment_key=bytes.fromhex(manifest['commitment_key_hex']),source_binding=bytes.fromhex(manifest['source_binding_hex']),deterministic_seed='00'*32,minimum_aggregate_occupancy=10,length_bounds=(0,1,4,8,16,32,64,128,256),numeric_boundaries=(-1000.,-100.,-10.,0.,10.,100.,1000.),max_inference_input_tokens=8192,preview_requested=True)
def scan(name,data):return oracle.EolympConnectorV1().scan_bytes(artifact_name=name,payload=data,**kwargs)
# Confirm this generation method reproduces every existing object byte for byte.
for entry in manifest['files']:
 if entry.get('refusal'):continue
 actual=signer.canonical_json_bytes(scan(entry['input'],(root/entry['input']).read_bytes())['objects'][0])
 assert actual == (root/entry['expected']).read_bytes(), entry['name']
cases={
 'signed_plus_csv':('csv',['+1']*20),
 'signed_unique_csv':('csv',['+'+str(i) for i in range(100,140)]),
 'signed_negative_csv':('csv',['-2']*20),
 'signed_mixed_csv':('csv',['+1']*10+['-2']*10),
 'padded_null_csv':('csv',['1']*10+[' NA ']*10+[' null ']*10+['2']*10),
 'nanosecond_jsonl':('jsonl',[f'2026-01-01T00:00:00.{i:09d}' for i in range(1,41)]),
 'nanosecond_csv':('csv',[f'2026-01-01T10:00:00.{123456780+i:09d}Z' for i in range(40)]),
 'nanosecond_exact_micro_csv':('csv',[f'2026-01-01T10:00:00.{(123450+i)*1000:09d}Z' for i in range(40)]),
 'fractional_jsonl':('jsonl',[f'2026-01-01T00:00:00.{123450+i:06d}Z' for i in range(40)]),
 'nanosecond_naive_csv':('csv',[f'2026-01-01T10:00:00.{123456780+i:09d}' for i in range(40)]),
 'microsecond_csv':('csv',[f'2026-01-01T10:00:00.{123450+i:06d}Z' for i in range(40)]),
 'millisecond_csv':('csv',[f'2026-01-01T10:00:00.{120+i:03d}Z' for i in range(40)]),
 'offset_csv':('csv',[f'2026-01-01T10:00:{i:02d}+05:30' for i in range(40)]),
 'offset_jsonl':('jsonl',[f'2026-01-01T10:00:{i:02d}+05:30' for i in range(40)]),
 'overflow_csv':('csv',['1e999']*20),
 'infinity_csv':('csv',['inf']*20),
 'negative_infinity_csv':('csv',['-inf']*20),
}
for name,(fmt,values) in cases.items():
 data=('n\n'+'\n'.join(values)+'\n').encode() if fmt=='csv' else ''.join(json.dumps({'n':v},separators=(',',':'))+'\n' for v in values).encode()
 try:
  result=scan(name+'.'+fmt,data);expected=signer.canonical_json_bytes(result['objects'][0]);refusal=False
  print(name,result['objects'][0]['column_types'],result['objects'][0]['approx_distinct_count'])
 except Exception as exc:
  expected=signer.canonical_json_bytes({'error':type(exc).__name__,'facts':None});refusal=True
  print(name,'REFUSAL',type(exc).__name__,str(exc))
 (root/(name+'.'+fmt)).write_bytes(data);(root/(name+'.facts.json')).write_bytes(expected)
 entry=dict(name=name,input=name+'.'+fmt,format=fmt,seed='00'*32,expected=name+'.facts.json',input_sha256=hashlib.sha256(data).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest())
 if refusal:entry['refusal']=True
 manifest['files']=[v for v in manifest['files'] if v['name']!=name]+[entry]
(root/'manifest.json').write_bytes(signer.canonical_json_bytes(manifest)+b'\n')
# Parquet timestamp[ns] exercises pandas' nine-digit isoformat path, independently
# of the CSV inference oracle. Preserve the unchanged connector/canonicalizer.
for name, zone in [('nanosecond_parquet', None), ('nanosecond_utc_parquet', 'UTC')]:
 values=[1767261600123456780+i for i in range(40)]
 assert all(value % 1000 != 0 for value in values)
 sink=pa.BufferOutputStream()
 pq.write_table(pa.table({'n':pa.array(values,type=pa.timestamp('ns',tz=zone))}),sink,compression='NONE',version='2.6')
 data=sink.getvalue().to_pybytes()
 obj=scan(name+'.parquet',data)['objects'][0]
 assert obj['column_types'] == ['datetime']
 expected=signer.canonical_json_bytes(obj)
 (root/(name+'.parquet')).write_bytes(data)
 (root/(name+'.facts.json')).write_bytes(expected)
 entry=dict(name=name,input=name+'.parquet',format='parquet',seed='00'*32,expected=name+'.facts.json',input_sha256=hashlib.sha256(data).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest())
 manifest['files']=[v for v in manifest['files'] if v['name']!=name]+[entry]
(root/'manifest.json').write_bytes(signer.canonical_json_bytes(manifest)+b'\n')
