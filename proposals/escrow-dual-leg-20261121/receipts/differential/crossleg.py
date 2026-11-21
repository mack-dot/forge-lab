import json, subprocess, sys, os
GV="/Users/mackianni/forge/.directives/leg2-implementer-packet/golden_vectors"
L1="/private/tmp/claude-501/-Users-mackianni-forge/fb0fde47-8987-485d-a625-0e9fdb4facee/scratchpad/leg1-escrow/leg1_cli.py"
L2="/private/tmp/claude-501/-Users-mackianni-forge/fb0fde47-8987-485d-a625-0e9fdb4facee/scratchpad/leg2-run2/src-extract/leg2-source/target/release/leg2-verify"
raw=json.load(open(os.path.join(GV,"vectors.json"))); cases=raw if isinstance(raw,list) else raw["cases"]
def p(f): return os.path.join(GV,f)
def args(c):
    a=[p(c["log_file"]),"--manifest",p(c["manifest_file"])]
    if c.get("pubkeys_file"):
        x,y=c["pubkeys_file"].split(","); a+=["--pubkeys",f"{p(x)},{p(y)}"]
    if c.get("tape_file"): a+=["--tape",p(c["tape_file"])]
    if c.get("observed_now") is not None: a+=["--observed-now",str(c["observed_now"])]
    if c.get("expect_tip"): a+=["--expect-tip",c["expect_tip"]]
    if c.get("max_records") is not None: a+=["--max-records",str(c["max_records"])]
    return a+["--json"]
def run(argv):
    r=subprocess.run(argv,capture_output=True,text=True)
    j=None
    for line in reversed(r.stdout.splitlines()):
        line=line.strip()
        if line.startswith("{"):
            try: j=json.loads(line); break
            except: pass
    if j is None:
        j={"_PARSE_FAIL":r.stdout[:150]}
    return j, r.returncode
l1_ok=l2_ok=xleg_ok=0; fails=[]
for c in cases:
    a=args(c)
    j1,e1=run([sys.executable,"-I",L1]+a)
    j2,e2=run([L2]+a)
    exp=c["expected_json"]
    d1=[k for k in exp if j1.get(k)!=exp[k]] or (["exit"] if e1!=exp["exit_code"] else [])
    d2=[k for k in exp if j2.get(k)!=exp[k]] or (["exit"] if e2!=exp["exit_code"] else [])
    xl=(j1!=j2) or (e1!=e2)
    if not d1: l1_ok+=1
    if not d2: l2_ok+=1
    if not xl: xleg_ok+=1
    if d1 or d2 or xl:
        fails.append((c["name"],{"leg1_vs_oracle":d1,"leg2_vs_oracle":d2,"leg1_vs_leg2_differ":xl,
                     "j1":{k:j1.get(k) for k in set(j1)|set(j2) if j1.get(k)!=j2.get(k)} if xl else None,
                     "j2":{k:j2.get(k) for k in set(j1)|set(j2) if j1.get(k)!=j2.get(k)} if xl else None}))
n=len(cases)
print("CASES %d | Leg1 vs oracle %d/%d | Leg2 vs oracle %d/%d | Leg1 vs Leg2 agree %d/%d"%(n,l1_ok,n,l2_ok,n,xleg_ok,n))
for name,d in fails: print("DIFF",name,json.dumps(d)[:400])
if not fails: print("ZERO DIFFS across all three comparisons.")
