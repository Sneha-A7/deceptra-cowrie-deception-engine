import json
from collections import Counter
from pathlib import Path
import streamlit as st
import pandas as pd

ROOT = Path.home() / "cowrie"
LOG = ROOT / "var/log/cowrie/cowrie.json"
PROFILE = ROOT / "deception_project/profiles/debian12.json"

st.set_page_config(page_title="Cowrie Deception Analysis", layout="wide")
st.title("Cowrie SSH Honeypot — Deception Analysis")
st.caption("Command-response consistency and attack-interaction analysis")

events = []
if LOG.exists():
    for line in LOG.read_text(errors="ignore").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
sessions = {e.get("session") for e in events if e.get("session")}
counts = Counter(e.get("input", "").strip() for e in commands if e.get("input", "").strip())

a, b, c = st.columns(3)
a.metric("Recorded commands", len(commands))
b.metric("SSH sessions", len(sessions))
c.metric("Unique commands", len(counts))

st.subheader("Most frequent commands")
if counts:
    df = pd.DataFrame(counts.most_common(10), columns=["Command", "Count"])
    st.bar_chart(df.set_index("Command"))
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No command events found in the Cowrie JSON log.")

st.subheader("Recent command activity")
if commands:
    recent = [
        {
            "Timestamp": e.get("timestamp", ""),
            "Session": e.get("session", ""),
            "Source IP": e.get("src_ip", ""),
            "Command": e.get("input", ""),
        }
        for e in commands[-50:]
    ]
    st.dataframe(pd.DataFrame(recent[::-1]), use_container_width=True, hide_index=True)

st.subheader("Deception consistency checks")
if PROFILE.exists():
    profile = json.loads(PROFILE.read_text())
    st.write(f"Target profile: **{profile['profile_name']}**")
    st.caption("Enter observed outputs from the controlled SSH test.")
    observed = {}
    for command in ["whoami", "hostname", "uname -r", "cat /etc/os-release"]:
        observed[command] = st.text_area(command, key=command, height=80)

    if st.button("Evaluate consistency"):
        expected = {
            "whoami": profile["identity"]["username"],
            "hostname": profile["hostname"],
            "uname -r": profile["kernel"]["release"],
        }
        results = []
        for command, value in expected.items():
            actual = observed[command].strip()
            results.append({
                "Command": command,
                "Expected": value,
                "Observed": actual,
                "Result": "PASS" if actual == value else "FAIL",
            })

        os_text = observed["cat /etc/os-release"]
        for field, value in {
            "ID": profile["os"]["id"],
            "VERSION_ID": profile["os"]["version_id"],
            "PRETTY_NAME": profile["os"]["pretty_name"],
        }.items():
            expected_line = f'{field}="{value}"'
            results.append({
                "Command": "cat /etc/os-release",
                "Expected": expected_line,
                "Observed": expected_line if expected_line in os_text.splitlines() else "Missing",
                "Result": "PASS" if expected_line in os_text.splitlines() else "FAIL",
            })

        result_df = pd.DataFrame(results)
        st.dataframe(result_df, use_container_width=True, hide_index=True)
        passed = (result_df["Result"] == "PASS").sum()
        st.metric("Consistency checks passed", f"{passed}/{len(results)}")
        st.download_button(
            "Download consistency results",
            result_df.to_csv(index=False),
            "consistency_results.csv",
            "text/csv",
        )

st.subheader("Evaluation status")
st.warning(
    "The dashboard currently displays logged command activity and interactive "
    "consistency checks. A valid baseline-versus-enhanced comparison requires "
    "separately recorded results from both test runs."
)
