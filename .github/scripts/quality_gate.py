#!/usr/bin/env python3
"""Quality gate: lee los reportes de seguridad y falla si hay hallazgos criticos."""
import argparse
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def semgrep(path):
    # Semgrep: severidad ERROR (o HIGH/CRITICAL en reglas nuevas) = critico
    out = []
    for r in load_json(path).get("results", []):
        sev = r.get("extra", {}).get("severity", "").upper()
        if sev in ("ERROR", "HIGH", "CRITICAL"):
            rule = r["check_id"].split(".")[-1]
            out.append(f"{rule}  {r['path']}:{r['start']['line']}")
    return out


def codeql(path, min_sev):
    # CodeQL SARIF: security-severity >= min_sev (9.0 = critical)
    files = glob.glob(os.path.join(path, "*.sarif")) if os.path.isdir(path) else [path]
    if not files:
        raise FileNotFoundError(f"no hay .sarif en {path}")
    out = []
    for f in files:
        for run in load_json(f).get("runs", []):
            tool = run.get("tool", {})
            rules = list(tool.get("driver", {}).get("rules", []) or [])
            for ext in tool.get("extensions", []) or []:
                rules += ext.get("rules", []) or []
            sev = {r["id"]: float(r.get("properties", {}).get("security-severity", 0)) for r in rules}
            for res in run.get("results", []):
                s = sev.get(res.get("ruleId"), 0.0)
                if s >= min_sev:
                    loc = res["locations"][0]["physicalLocation"]
                    line = loc.get("region", {}).get("startLine")
                    out.append(f"{res['ruleId']} (sev {s})  {loc['artifactLocation']['uri']}:{line}")
    return out


def spotbugs(path, max_rank, sec_priority):
    # SpotBugs: rank 1-4 ("scariest") o categoria SECURITY con prioridad alta/media
    out = []
    for b in ET.parse(path).getroot().iter("BugInstance"):
        rank = int(b.get("rank", "20"))
        priority = int(b.get("priority", "3"))
        security = b.get("category") == "SECURITY" and priority <= sec_priority
        if rank <= max_rank or security:
            src = b.find("SourceLine")
            loc = f"{src.get('sourcepath')}:{src.get('start')}" if src is not None else ""
            out.append(f"{b.get('type')} (rank {rank}, prioridad {priority})  {loc}")
    return out


def depcheck(path, min_cvss):
    # OWASP Dependency-Check: severidad CRITICAL o CVSS >= min_cvss
    out = []
    for d in load_json(path).get("dependencies", []):
        for v in d.get("vulnerabilities", []) or []:
            score = (v.get("cvssv3") or {}).get("baseScore") or (v.get("cvssv2") or {}).get("score") or 0
            if v.get("severity", "").upper() == "CRITICAL" or float(score) >= min_cvss:
                out.append(f"{v.get('name')} (CVSS {score})  {d.get('fileName')}")
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--semgrep")
    p.add_argument("--codeql")
    p.add_argument("--spotbugs")
    p.add_argument("--depcheck")
    p.add_argument("--codeql-min", type=float, default=9.0)
    p.add_argument("--spotbugs-max-rank", type=int, default=4)
    p.add_argument("--spotbugs-sec-priority", type=int, default=2)
    p.add_argument("--cvss-min", type=float, default=9.0)
    a = p.parse_args()

    checks = [
        ("Semgrep", a.semgrep, lambda x: semgrep(x)),
        ("CodeQL", a.codeql, lambda x: codeql(x, a.codeql_min)),
        ("SpotBugs", a.spotbugs, lambda x: spotbugs(x, a.spotbugs_max_rank, a.spotbugs_sec_priority)),
        ("Dependency-Check", a.depcheck, lambda x: depcheck(x, a.cvss_min)),
    ]

    failed = False
    rows = []
    for name, path, fn in checks:
        if not path:
            continue
        if not os.path.exists(path):
            # Un reporte ausente no es "cero hallazgos": el gate falla
            print(f"::error::{name}: no se encontro el reporte {path}")
            rows.append((name, "SIN REPORTE", "-"))
            failed = True
            continue
        try:
            found = fn(path)
        except Exception as e:  # reporte corrupto o formato inesperado
            print(f"::error::{name}: no se pudo leer {path}: {e}")
            rows.append((name, "ERROR LECTURA", "-"))
            failed = True
            continue
        print(f"== {name}: {len(found)} hallazgo(s) critico(s)")
        for f in found:
            print(f"   - {f}")
        if found:
            print(f"::error::{name}: {len(found)} hallazgo(s) critico(s)")
            failed = True
        rows.append((name, "FALLA" if found else "OK", str(len(found))))

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as s:
            s.write("## Quality Gate\n\n| Herramienta | Estado | Criticos |\n|---|---|---|\n")
            for r in rows:
                s.write(f"| {r[0]} | {r[1]} | {r[2]} |\n")

    print("Quality gate: FALLA" if failed else "Quality gate: OK")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
