import json

BEFORE = "vulnerability-report.json"
AFTER = "vulnerability-report-v3.json"


def get_counts(filename):
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    high = 0
    critical = 0

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "").upper()

            if severity == "HIGH":
                high += 1
            elif severity == "CRITICAL":
                critical += 1

    return high, critical


before_high, before_critical = get_counts(BEFORE)
after_high, after_critical = get_counts(AFTER)

before_total = before_high + before_critical
after_total = after_high + after_critical

print("\n===== REMEDIATION VERIFICATION =====\n")

print(f"BEFORE:")
print(f"  HIGH:     {before_high}")
print(f"  CRITICAL: {before_critical}")
print(f"  TOTAL:    {before_total}")

print(f"\nAFTER:")
print(f"  HIGH:     {after_high}")
print(f"  CRITICAL: {after_critical}")
print(f"  TOTAL:    {after_total}")

print("\n-----------------------------------")

if after_total < before_total:
    print("[SUCCESS] Security improved.")
    print(f"[+] Vulnerabilities reduced by {before_total - after_total}")
elif after_total == before_total:
    print("[NO IMPROVEMENT] Vulnerability count did not decrease.")
    print("[!] The system must not claim successful remediation.")
else:
    print("[FAILED] Security became worse.")
    print("[!] Rollback should be triggered.")

print("-----------------------------------\n")