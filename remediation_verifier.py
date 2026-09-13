import json

BEFORE = "vulnerability-report-v5.json"
AFTER = "vulnerability-report-v6.json"


def load_findings(filename):
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            findings.append(vuln)

    return findings


def count_severity(findings, severity):
    return sum(
        1 for vuln in findings
        if vuln.get("Severity", "").upper() == severity
    )


before = load_findings(BEFORE)
after = load_findings(AFTER)

before_total = len(before)
after_total = len(after)

print("\n===== SELF-HEALING VERIFICATION =====\n")

print("BEFORE (v5)")
print(f"  CRITICAL: {count_severity(before, 'CRITICAL')}")
print(f"  HIGH:     {count_severity(before, 'HIGH')}")
print(f"  MEDIUM:   {count_severity(before, 'MEDIUM')}")
print(f"  TOTAL:    {before_total}")

print("\nAFTER (v6)")
print(f"  CRITICAL: {count_severity(after, 'CRITICAL')}")
print(f"  HIGH:     {count_severity(after, 'HIGH')}")
print(f"  MEDIUM:   {count_severity(after, 'MEDIUM')}")
print(f"  TOTAL:    {after_total}")

reduction = before_total - after_total

print("\n===== SYSTEM DECISION =====")

if reduction > 0:
    print("[PASS] Security posture improved.")
    print(f"[+] Findings reduced by {reduction}.")
    print("[+] Candidate image can proceed to health testing.")

elif reduction == 0:
    print("[FAIL] No security improvement.")
    print("[!] Candidate image must not be deployed automatically.")

else:
    print("[FAIL] Security became worse.")
    print("[!] Rollback required.")


print("\n====================================\n")