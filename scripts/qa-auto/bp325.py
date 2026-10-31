"""buildpacks #325 end-to-end: `check cncf --project buildpacks` on lifecycle-config pairs (11 cases).
usage: bp325.py <prufyx binary> <workdir> [--cases FILE]
An honest/lying proposal that must be refused (expected exits exclude 0) but exits 0 is a WRONGPASS;
any other unexpected exit is a MISMATCH. --cases writes the qa-auto case list."""
import json,subprocess,os,sys
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from qalib import case,dump
P=sys.argv[1]; W=sys.argv[2]; os.makedirs(W,exist_ok=True)
CASES=[]
DEP=["0.3","0.4","0.5","0.6"]; S0=["0.3","0.4","0.5","0.6","0.7","0.8","0.9","0.10","0.11"]; S1=S0+["0.12"]
def cfg(path,ver,sup,dep=DEP,drop_apis=False):
    apis=json.dumps({"buildpack":{"supported":["0.9"],"deprecated":[]},"platform":{"supported":sup,"deprecated":dep}})
    lab={"io.buildpacks.lifecycle.version":ver,"io.buildpacks.builder.metadata":json.dumps({"lifecycle":{"version":ver}})}
    if not drop_apis: lab["io.buildpacks.lifecycle.apis"]=apis
    json.dump({"architecture":"arm64","history":[],"config":{"Labels":lab}},open(path,"w")); os.chmod(path,0o600)
def run(name,cur,prop,api,frm="0.16.5",to="0.17.7",expect=None):
    c=f"{W}/{name}-c.json"; p=f"{W}/{name}-p.json"
    cur(c); prop(p)
    r=subprocess.run([P,"check","cncf","--project","buildpacks","--current-lifecycle-config",c,"--proposed-lifecycle-config",p,"--from",frm,"--to",to,"--current-platform-api","0.11","--proposed-platform-api",api,"--now","2026-09-10T17:00:00Z","--format","json"],capture_output=True,text=True)
    try: j=json.loads(r.stdout); v=j.get("verdict") or j.get("result",{}).get("status")
    except Exception: v="?"
    ok = r.returncode in expect
    print(("OK  " if ok else "FAIL"),name,"exit",r.returncode,v,"expected",expect, "" if ok else r.stdout[:200]+r.stderr[:200])
    CASES.append(case("bp325",name,wrongpass=(not ok and r.returncode==0 and 0 not in expect),mismatch=(not ok and not (r.returncode==0 and 0 not in expect)),exit=r.returncode,verdict=v,expect=expect))
H=lambda ver,sup,**k:(lambda path:cfg(path,ver,sup,**k))
run("honest-0.12",H("0.16.5",S0),H("0.17.7",S1),"0.12",expect=[0])
run("honest-0.13-blocked",H("0.16.5",S0),H("0.17.7",S1),"0.13",expect=[10,11])
run("lie-target-0.13",H("0.16.5",S0),H("0.17.7",S1+["0.13"]),"0.13",expect=[11,10])
run("lie-target-0.13-api0.12",H("0.16.5",S0),H("0.17.7",S1+["0.13"]),"0.12",expect=[11])
run("lie-current-extra",H("0.16.5",S0+["0.12"]),H("0.17.7",S1),"0.12",expect=[11])
run("lie-current-missing",H("0.16.5",S0[:8]),H("0.17.7",S1),"0.12",expect=[11])
run("lie-target-missing-0.12",H("0.16.5",S0),H("0.17.7",S0),"0.12",expect=[11,10])
run("deprecated-mismatch",H("0.16.5",S0),H("0.17.7",S1,dep=["0.3"]),"0.12",expect=[11])
run("deprecated-empty",H("0.16.5",S0),H("0.17.7",S1,dep=[]),"0.12",expect=[11])
run("unreviewed-ver",H("0.16.5",S0),H("0.17.6",S1),"0.12",to="0.17.6",expect=[11,2,3])
run("no-apis-label",H("0.16.5",S0),(lambda p:cfg(p,"0.17.7",S1,drop_apis=True)),"0.12",expect=[11])

if "--cases" in sys.argv: dump(CASES,sys.argv[sys.argv.index("--cases")+1])
print("bp325 wrongpass",sum(c["wrongpass"] for c in CASES),"mismatch",sum(c["mismatch"] for c in CASES))
