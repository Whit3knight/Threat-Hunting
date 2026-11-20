#!/usr/bin/env python3
"""Re-derive every headline number in the report artifacts straight from the parquet.
Usage:  uv run --with duckdb python cek_ulang_angka.py
Exit code 0 = all checks PASS. Each line prints actual vs expected.
"""
import duckdb, json, sys, os

LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data") + "/"
CACHE = "/home/whit3knight/.hermes/cache/scratch/p6/"
P = LOCAL if os.path.exists(LOCAL + "signals.parquet") else CACHE
NEED = ["signals.parquet", "attack_reports.parquet"]
missing = [f for f in NEED if not os.path.exists(P + f)]
if missing:
    print("MISSING:", missing)
    print("Re-download (force IPv4, HF rate-limits IPv6):")
    print("  mkdir -p", P)
    for f in missing:
        sub = "signals/signals.parquet" if f == "signals.parquet" else "graph/" + f
        print(f"  curl -4 -sL https://huggingface.co/datasets/witfoo/precinct6-cybersecurity/resolve/main/{sub} -o {P}{f}")
    sys.exit(2)

c = duckdb.connect()
c.execute(f"CREATE VIEW sig AS SELECT * FROM '{P}signals.parquet'")
c.execute(f"CREATE VIEW rep AS SELECT * FROM '{P}attack_reports.parquet'")

fails = 0
def check(label, actual, expected):
    global fails
    ok = actual == expected
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {label:52} actual={actual}  expected={expected}")

# 1. dataset size + labels
check("total rows in signals", c.sql("SELECT count(*) FROM sig").fetchall()[0][0], 2011674)
for lab, exp in (("benign", 1897153), ("suspicious", 106793), ("malicious", 7728)):
    check(f"label {lab}", c.sql(f"SELECT count(*) FROM sig WHERE label_binary='{lab}'").fetchall()[0][0], exp)

# 2. VPC flow integrity
check("vpc flow rows", c.sql("SELECT count(*) FROM sig WHERE stream_name='aws_vpc_flow_log'").fetchall()[0][0], 19219)
check("vpc flow direction inverted", c.sql("""SELECT count(*) FROM sig WHERE stream_name='aws_vpc_flow_log'
      AND str_split(message_sanitized,' ')[4] = dst_ip""").fetchall()[0][0], 3287)
check("vpc flow actions distinct", str(c.sql("""SELECT DISTINCT str_split(message_sanitized,' ')[13]
      FROM sig WHERE stream_name='aws_vpc_flow_log'""").fetchall()), str([('REJECT',)]))

# 3. EDR behaviors + devices
rows = c.sql("SELECT message_sanitized FROM sig WHERE stream_name='Crowdstrike Detection'").fetchall()
beh, devices = set(), set()
for (m,) in rows:
    i = m.index("message=")
    d, _ = json.JSONDecoder().raw_decode(m[i + 8:].lstrip())
    devices.add((d.get("device") or {}).get("device_id"))
    for b in d.get("behaviors", []):
        beh.add((b.get("device_id"), b.get("behavior_id"), b.get("timestamp"), b.get("cmdline")))
check("crowdstrike artifacts", len(rows), 58)
check("unique EDR behaviors", len(beh), 7)
check("distinct EDR devices", len(devices), 2)
check("tamper behaviors blocked", c.sql("""SELECT count(*) FROM sig WHERE stream_name='Crowdstrike Detection'
      AND message_sanitized LIKE '%FileSystemTamper%' AND message_sanitized LIKE '%"fs_operation_blocked":true%'""").fetchall()[0][0] > 0, True)

# 4. H2 signatures (payload-based)
s2 = c.sql("""SELECT count(*), count(DISTINCT str_split(message_sanitized,' ')[7])
   FROM sig WHERE stream_name='aws_vpc_flow_log'
   AND str_split(message_sanitized,' ')[5]='10.98.236.105'
   AND CAST(str_split(message_sanitized,' ')[11] AS BIGINT) BETWEEN 1722285357 AND 1722285960""").fetchall()[0]
check("S2 flows to 10.98.236.105 (20:35-20:41 UTC)", s2[0], 9920)
check("S2 distinct dst ports", s2[1], 102)
s2b = c.sql("""SELECT count(*), count(DISTINCT str_split(message_sanitized,' ')[7])
   FROM sig WHERE stream_name='aws_vpc_flow_log' AND str_split(message_sanitized,' ')[4]='100.64.27.187'""").fetchall()[0]
check("100.64.27.187 flows / ports", (s2b[0], s2b[1]), (5218, 55))

# 5. baseline + calibration
check("distinct flow sources", c.sql("""SELECT count(DISTINCT str_split(message_sanitized,' ')[4])
      FROM sig WHERE stream_name='aws_vpc_flow_log'""").fetchall()[0][0], 215)
cal = c.sql("""WITH p AS (SELECT str_split(message_sanitized,' ')[4] s,
   CAST(str_split(message_sanitized,' ')[7] AS VARCHAR) dp,
   CAST(str_split(message_sanitized,' ')[11] AS BIGINT) t FROM sig WHERE stream_name='aws_vpc_flow_log'),
 w AS (SELECT s,(t//300) win,count(DISTINCT dp) ports FROM p GROUP BY s,win)
 SELECT count(*) FROM w WHERE ports>=10""").fetchall()[0][0]
check("5-min windows with >=10 ports", cal, 3)

# 6. correlation gap
check("incidents in attack_reports", c.sql("SELECT count(*) FROM rep").fetchall()[0][0], 51371)
mixed = c.sql("""WITH e AS (SELECT unnest(from_json(incident_ids,'["VARCHAR"]')) iid, stream_name
   FROM sig WHERE incident_ids IS NOT NULL AND incident_ids NOT IN ('[]','')),
 g AS (SELECT iid FROM e GROUP BY 1
   HAVING list_contains(list(DISTINCT stream_name),'Crowdstrike Detection')
      AND list_contains(list(DISTINCT stream_name),'aws_vpc_flow_log'))
 SELECT count(*) FROM g""").fetchall()[0][0]
check("incidents mixing EDR + flow (expect 0 = gap)", mixed, 0)

print()
print("RESULT:", "ALL PASS" if fails == 0 else f"{fails} CHECK(S) FAILED")
sys.exit(0 if fails == 0 else 1)
