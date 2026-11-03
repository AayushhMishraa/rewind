#!/usr/bin/env python3
"""Evaluation harness: run the live scenarios several times, report reliability and runtime.

For each run it starts pytest on the scenario files (unit tests are excluded), reads the JUnit XML,
and then prints a markdown table: how often each scenario passed, plus its MEDIAN and WORST-CASE
runtime. Every scenario builds its own temporary sandbox, so runs cannot affect each other.

  python3 evaluation/run_eval.py                                   # 5 runs of everything (~15-20 min)
  python3 evaluation/run_eval.py --runs 2 --keyword "s2_ or s3b"   # quick check
Results are also written to evaluation/results.md and evaluation/results.json.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FILES = ["tests/test_integration.py", "tests/test_acceptance.py", "tests/test_step7.py"]


def scenario_id(name):
    parts = name.split("_")[1:]                     # drop the leading "test"
    if parts and parts[0] == "scenario":
        parts = parts[1:]
    if parts[:2] == ["s1", "live"]:
        return "S1-LIVE"
    return parts[0].upper() if parts else name


def run_once(index, keyword, workdir):
    """One pytest run. Returns ({test name: {ok, seconds}}, wall seconds)."""
    xml_path = os.path.join(workdir, "run%d.xml" % index)
    expr = "not test_unit_" if not keyword else "(%s) and not test_unit_" % keyword
    cmd = [sys.executable, "-m", "pytest", *FILES, "-q", "-p", "no:cacheprovider",
           "-k", expr, "--junitxml", xml_path]
    started = time.time()
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    wall = time.time() - started
    results = {}
    try:
        for case in ET.parse(xml_path).getroot().iter("testcase"):
            bad = (case.find("failure") is not None or case.find("error") is not None
                   or case.find("skipped") is not None)
            results[case.get("name")] = {"ok": not bad, "seconds": float(case.get("time") or 0.0)}
    except (OSError, ET.ParseError):
        print("run %d: pytest produced no readable XML (exit %s)\n%s"
              % (index, proc.returncode, proc.stdout[-600:]), file=sys.stderr)
    return results, wall


def main():
    parser = argparse.ArgumentParser(description="Run the live scenarios N times.")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--keyword", default=None, help='pytest -k expression, e.g. "s2_ or s3b"')
    args = parser.parse_args()
    per_test, total_wall = {}, 0.0
    with tempfile.TemporaryDirectory() as workdir:
        for i in range(1, args.runs + 1):
            results, wall = run_once(i, args.keyword, workdir)
            total_wall += wall
            print("run %d/%d: %d scenarios, %d failed, %.0f s"
                  % (i, args.runs, len(results), sum(1 for r in results.values() if not r["ok"]),
                     wall), file=sys.stderr)
            for name, r in results.items():
                per_test.setdefault(name, []).append(r)
    rows, all_green = [], bool(per_test)
    for name in sorted(per_test):
        runs = per_test[name]
        passed = sum(1 for r in runs if r["ok"])
        times = [r["seconds"] for r in runs]
        all_green = all_green and passed == args.runs
        rows.append({"scenario": scenario_id(name), "test": name, "runs": len(runs),
                     "passed": passed, "median_s": round(statistics.median(times), 1),
                     "worst_s": round(max(times), 1)})
    lines = ["# Rewind evaluation: %d run(s) per scenario" % args.runs, "",
             "Generated: %s. Total wall time: %.0f s." % (time.strftime("%Y-%m-%d %H:%M"), total_wall),
             "", "| Scenario | Test | Runs | Passed | Median (s) | Worst (s) |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| %s | %s | %d | %d/%d | %.1f | %.1f |" % (
            r["scenario"], r["test"], r["runs"], r["passed"], r["runs"], r["median_s"], r["worst_s"]))
    lines += ["", "Result: %s" % ("ALL GREEN" if all_green else "FAILURES PRESENT")]
    table = "\n".join(lines) + "\n"
    print(table)
    with open(os.path.join(HERE, "results.md"), "w", encoding="utf-8") as f:
        f.write(table)
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"runs": args.runs, "keyword": args.keyword, "wall_seconds": round(total_wall, 1),
                   "scenarios": rows}, f, indent=2)
    sys.exit(0 if all_green else 1)


if __name__ == "__main__":
    main()
