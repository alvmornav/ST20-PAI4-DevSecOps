import argparse
import csv
import json
import os
import sys

from rol_b_parsers import PARSERS_ROL_B

ZAP_RISK = ["Informational", "Low", "Medium", "High"]


def zap_ignored(rules_file):
    if not rules_file or not os.path.exists(rules_file):
        return set()
    with open(rules_file, encoding="utf-8") as f:
        return {row[0].strip() for row in csv.reader(f, delimiter="\t") if len(row) > 1 and row[1].strip() == "IGNORE"}


def zap(report, threshold, ignore):
    with open(report, encoding="utf-8") as f:
        data = json.load(f)
    minimum = ZAP_RISK.index(threshold)
    skip = zap_ignored(ignore)
    rows = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            if risk >= minimum and str(alert.get("pluginid")) not in skip:
                rows.append((ZAP_RISK[risk], alert.get("name", alert.get("alert", "?")), f"{alert.get('count', '?')} instancias"))
    return rows


PARSERS = {"zap": zap, **PARSERS_ROL_B}


def summary(tool, threshold, mode, rows):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    modo = "aviso" if mode == "warn" else "bloqueante"
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"### Quality gate {tool} ({modo}, umbral {threshold})\n\n")
        f.write(f"Hallazgos que superan el umbral: **{len(rows)}**\n\n")
        if rows:
            f.write("| Severidad | Hallazgo | Detalle |\n| --- | --- | --- |\n")
            for sev, name, detail in rows[:50]:
                f.write(f"| {sev} | {name} | {detail} |\n")
            if len(rows) > 50:
                f.write(f"\n... y {len(rows) - 50} más (ver informe completo en los artefactos)\n")
        f.write("\n")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tool", required=True, choices=sorted(PARSERS))
    p.add_argument("--report", required=True)
    p.add_argument("--threshold", required=True)
    p.add_argument("--mode", choices=["warn", "block"], default="block")
    p.add_argument("--ignore")
    a = p.parse_args()

    level = "warning" if a.mode == "warn" else "error"
    if not os.path.isfile(a.report) or os.path.getsize(a.report) == 0:
        print(f"::{level} title=Quality gate {a.tool}::No existe el informe {a.report}")
        sys.exit(1)

    rows = PARSERS[a.tool](a.report, a.threshold, a.ignore)
    summary(a.tool, a.threshold, a.mode, rows)
    if not rows:
        print(f"Quality gate {a.tool}: superado (umbral {a.threshold})")
        return
    print(f"::{level} title=Quality gate {a.tool}::{len(rows)} hallazgos superan el umbral {a.threshold}")
    sys.exit(1)


if __name__ == "__main__":
    main()
