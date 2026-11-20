import json
import xml.etree.ElementTree as ET

SEMGREP_LEVELS = ["INFO", "WARNING", "ERROR"]
TRIVY_LEVELS = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def dependency_check(report, threshold, ignore):
    root = ET.parse(report).getroot()
    tag = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    rows = []
    for dep in root.iter(f"{tag}dependency"):
        scores = []
        for v in dep.iter(f"{tag}vulnerability"):
            score = v.find(f"{tag}cvssV3/{tag}baseScore")
            if score is not None and score.text:
                scores.append((float(score.text), v.findtext(f"{tag}name")))
        if scores:
            top, cve = max(scores)
            if top >= float(threshold):
                rows.append((str(top), dep.findtext(f"{tag}fileName"), cve))
    return rows


def semgrep(report, threshold, ignore):
    with open(report, encoding="utf-8") as f:
        data = json.load(f)
    minimum = SEMGREP_LEVELS.index(threshold)
    rows = []
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "INFO")
        if sev in SEMGREP_LEVELS and SEMGREP_LEVELS.index(sev) >= minimum:
            rows.append((sev, r["check_id"].split(".")[-1], f"{r['path']}:{r['start']['line']}"))
    return rows


def checkov(report, threshold, ignore):
    with open(report, encoding="utf-8") as f:
        data = json.load(f)
    blocks = data if isinstance(data, list) else [data]
    rows = []
    for b in blocks:
        for c in b.get("results", {}).get("failed_checks", []):
            rows.append(("FAILED", c["check_id"], f"{c['file_path']}:{c['resource']}"))
    return rows if len(rows) >= int(threshold) else []


def trivy(report, threshold, ignore):
    with open(report, encoding="utf-8") as f:
        data = json.load(f)
    minimum = TRIVY_LEVELS.index(threshold)
    rows = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN")
            if sev in TRIVY_LEVELS and TRIVY_LEVELS.index(sev) >= minimum and v.get("FixedVersion"):
                rows.append((sev, v["VulnerabilityID"], f"{v['PkgName']} {v['InstalledVersion']} -> {v['FixedVersion']}"))
    return rows


PARSERS_ROL_B = {
    "dependency-check": dependency_check,
    "semgrep": semgrep,
    "checkov": checkov,
    "trivy": trivy,
}
