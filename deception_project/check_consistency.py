import json
from pathlib import Path

PROFILE_PATH = Path(__file__).parent / "profiles" / "debian12.json"


def load_profile():
    with PROFILE_PATH.open(encoding="utf-8") as file:
        return json.load(file)


def check_responses(profile, responses):
    expected = {
        "whoami": profile["identity"]["username"],
        "hostname": profile["hostname"],
        "uname -r": profile["kernel"]["release"],
    }

    os_release = responses.get("cat /etc/os-release", "")
    results = []

    for command, expected_value in expected.items():
        observed = responses.get(command, "").strip()
        passed = observed == expected_value

        results.append({
            "command": command,
            "expected": expected_value,
            "observed": observed,
            "passed": passed,
        })

    # Check OS-release content separately because it contains multiple fields.
    required_os_fields = {
        "ID": profile["os"]["id"],
        "VERSION_ID": profile["os"]["version_id"],
        "PRETTY_NAME": profile["os"]["pretty_name"],
    }

    for field, expected_value in required_os_fields.items():
        expected_line = f'{field}="{expected_value}"'
        passed = expected_line in os_release.splitlines()

        results.append({
            "command": "cat /etc/os-release",
            "field": field,
            "expected": expected_line,
            "observed": os_release,
            "passed": passed,
        })

    return results


def main():
    profile = load_profile()

    # These are the baseline observations captured during our experiment.
    # The OS-release response was empty; other responses matched the profile.
    baseline = {
        "whoami": "root",
        "hostname": "svr04",
        "uname -r": "6.1.0-21-amd64",
        "cat /etc/os-release": "",
    }

    results = check_responses(profile, baseline)
    passed = sum(result["passed"] for result in results)
    failed = len(results) - passed

    print(f"Profile: {profile['profile_name']}")
    print(f"Checks: {len(results)} | Passed: {passed} | Failed: {failed}")
    print()

    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        label = result["command"]

        if "field" in result:
            label += f' [{result["field"]}]'

        print(f"[{status}] {label}")
        if not result["passed"]:
            print(f"       Expected: {result['expected']}")
            print(f"       Observed: {result['observed']!r}")


if __name__ == "__main__":
    main()
