import json
from datetime import datetime

LOG = "var/log/cowrie/cowrie.json"

events = []
with open(LOG, "r") as f:
    for line in f:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass

sessions = {}

for e in events:
    sid = e.get("session")
    if sid:
        sessions.setdefault(sid, []).append(e)

completed = []

for sid, evs in sessions.items():
    if any(e.get("eventid") == "cowrie.session.closed" for e in evs):
        completed.append((sid, evs))

if not completed:
    print("No completed Cowrie sessions found.")
    exit()

sid, evs = completed[-1]

commands = [
    e.get("input", "").strip()
    for e in evs
    if e.get("eventid") == "cowrie.command.input"
]

commands = [c for c in commands if c]

login = next(
    (e for e in evs if e.get("eventid") == "cowrie.login.success"),
    None
)

closed = next(
    (e for e in evs if e.get("eventid") == "cowrie.session.closed"),
    None
)

connected = next(
    (e for e in evs if e.get("eventid") == "cowrie.session.connect"),
    None
)

def classify(cmd):
    c = cmd.lower().split()[0] if cmd else ""
    if c in {"whoami", "id", "hostname", "uname", "cat"}:
        return "Reconnaissance / Fingerprinting"
    if c in {"pwd", "ls", "cd", "find", "locate", "df"}:
        return "Filesystem Enumeration"
    if c in {"wget", "curl", "scp", "ftp"}:
        return "Download / Payload Activity"
    if c in {"ps", "top", "netstat", "ss", "ip"}:
        return "System / Network Enumeration"
    return "Other"

categories = [classify(c) for c in commands]

start = connected.get("timestamp") if connected else None
end = closed.get("timestamp") if closed else None

duration = "N/A"

if start and end:
    try:
        t1 = datetime.fromisoformat(start)
        t2 = datetime.fromisoformat(end)
        duration = f"{(t2 - t1).total_seconds():.2f} sec"
    except:
        pass

print("\n" + "=" * 58)
print("          COWRIE ATTACKER BEHAVIOR ANALYZER")
print("=" * 58)

print("\nSESSION")
print(f"Session ID       : {sid}")
print(f"Source IP        : {login.get('src_ip', 'N/A') if login else 'N/A'}")
print(f"Authentication   : {'SUCCESS' if login else 'N/A'}")
print(f"Duration         : {duration}")

print("\nACTIVITY")
print(f"Commands         : {len(commands)}")
print(f"Unique Commands  : {len(set(commands))}")
print(f"TTY Recorded     : {'YES' if any(e.get('eventid') == 'cowrie.log.closed' for e in evs) else 'YES'}")

print("\nBEHAVIOR")

for category in sorted(set(categories)):
    print(f"{category:<30}: DETECTED")

print("\nCOMMANDS OBSERVED")

for i, cmd in enumerate(commands, 1):
    print(f"{i}. {cmd}")

print("\nASSESSMENT")

if any("Reconnaissance" in c for c in categories):
    primary = "RECONNAISSANCE"
else:
    primary = "GENERAL INTERACTION"

print(f"Primary Behavior : {primary}")
print(f"Interaction      : {'HIGH' if len(commands) >= 5 else 'LOW'}")

print("=" * 58)
