"""Render finalized, independently audited result summaries; never run benchmarks.

Run only after all performance measurement has stopped:
    python ready_tables.py

This script imports only the standard library. It does not bootstrap again or
open raw service snapshots. It validates the published summaries, the lifecycle
CSV/manifest, and the small per-run retained-history observations before writing
any TeX tables. Existing manuscript hooks are filled; sections are not edited.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
from statistics import fmean


LIFECYCLE_SEEDS = 30  # paired seeds per lifecycle cell (2026110901-2026110930)
LIFECYCLE_RUNS = 13*3*LIFECYCLE_SEEDS  # nine synthetic + four workflow cells, three policies
POLICIES = ("full_sql", "guarded_full", "adaptive_delta")
BASELINES = POLICIES[:2]
LABELS = {"full_sql": "Full SQL", "guarded_full": "Guarded full", "adaptive_delta": r"Adaptive $\Delta$"}
SCENARIOS = ("all_valid", "unrelated_refresh", "benign_shared_refresh", "baseline_withdrawal")
SCENARIO_LABELS = {"all_valid": "All valid", "unrelated_refresh": "Unrelated refresh",
                   "benign_shared_refresh": "Shared refresh", "baseline_withdrawal": "Baseline withdrawal"}
LIFECYCLE_METRICS = ("one_time_setup.wall_ms", "operational_lifecycle.wall_ms", "full_lifecycle.wall_ms",
                     "operational_lifecycle.cpu_ms", "full_lifecycle.cpu_ms", "operational_writer_ms")
DELTA_METRICS = ("full_lifecycle.wall_ms", "operational_lifecycle.wall_ms", "operational_writer_ms")
SERVICE_METRICS = ("arrival_to_completion_p95_ms", "arrival_to_completion_p99_ms", "measurement_goodput_per_s",
                   "settle_validation_mean_ms", "refresh_mutation_log_mean_ms")
SERVICE_SCALES = (1, 1, 1, 1000, 1000)
SERVICE_DIGITS = (2, 2, 3, 2, 2)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def finite(value):
    require(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value),
            f"Expected finite numeric value, found {value!r}")
    return float(value)


def num(value, digits=2):
    value = finite(value)
    if abs(value) < .5*10**-digits:
        value = 0.0
    return f"{value:.{digits}f}"


def integer(value):
    require(finite(value).is_integer(), f"Expected integer: {value!r}")
    return str(int(value))


def tex_escape(value):
    return str(value).replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")


class Inputs:
    def __init__(self, root):
        self.root = root
        self.hashes = {}

    def raw(self, path):
        path = Path(path)
        raw = path.read_bytes()
        self.hashes[path.relative_to(self.root).as_posix()] = hashlib.sha256(raw).hexdigest()
        return raw

    def json(self, path):
        return json.loads(self.raw(path))

    def csv(self, path):
        return list(csv.DictReader(io.StringIO(self.raw(path).decode("utf-8-sig"))))


def interval(stat, *, lifecycle=False, scale=1, n=5, digits=2):
    if lifecycle:
        require(stat["n_runs"] == LIFECYCLE_SEEDS and len(stat["values"]) == LIFECYCLE_SEEDS, "Lifecycle interval has wrong seed count")
        lower, upper = stat["paired_bootstrap_95ci"]
    else:
        require(stat["n"] == n, "Service interval has wrong seed count")
        lower, upper = stat["ci95_low"], stat["ci95_high"]
    lower, upper, mean = finite(lower), finite(upper), finite(stat["mean"])
    require(lower <= upper, "Reversed interval")
    return r"\shortstack[r]{"+num(mean*scale,digits)+r"\\[-1pt]$["+num(lower*scale,digits)+r",\ "+num(upper*scale,digits)+r"]$}"


def table(caption, label, columns, headers, rows, note=""):
    return (r"\begin{table}[!htbp]"+"\n"+r"\centering\fontsize{9}{11}\selectfont"+"\n"
            +r"\setlength{\tabcolsep}{3pt}"+"\n"+r"\renewcommand{\arraystretch}{1.12}"+"\n"
            +r"\caption{"+caption+"}\n"+r"\label{"+label+"}\n"
            +r"\begin{tabular}{@{}"+columns+r"@{}}"+"\n"+r"\toprule"+"\n"
            +" & ".join(headers)+r" \\"+"\n"+r"\midrule"+"\n"
            +"\n".join(" & ".join(row)+r" \\" if isinstance(row, list) else row for row in rows)
            +"\n"+r"\bottomrule"+"\n"+r"\end{tabular}"+"\n"
            +(r"\par\smallskip\begin{minipage}{\linewidth}\fontsize{9}{11}\selectfont "+note+r"\end{minipage}"+"\n" if note else "")
            +r"\end{table}"+"\n")


def lifecycle_inputs(reader, root):
    folder = root/"results/lifecycle"
    summary, manifest = reader.json(folder/"summary.json"), reader.json(folder/"manifest.json")
    csv_rows = reader.csv(folder/"run_totals.csv")
    require(summary["status"] == "passed" and manifest["status"] == "completed", "Lifecycle cohort is unfinished or invalid")
    require(summary["completed_runs"] == manifest["requested_runs"] == manifest["completed_runs"] == len(csv_rows) == LIFECYCLE_RUNS,
            f"Expected all {LIFECYCLE_RUNS} lifecycle runs")
    declared = {row["run_id"]: row for row in manifest["runs"]}
    require(len(declared) == len(manifest["runs"]) == LIFECYCLE_RUNS and all(row["status"] == "completed" for row in declared.values()),
            "Lifecycle manifest contains duplicate, missing or failed runs")
    rows = {}
    for row in csv_rows:
        key = row["family"], row["name"], int(row["seed"]), row["policy"]
        require(key not in rows, "Duplicate lifecycle CSV pairing key")
        rows[key] = row
        run_id = f"{key[0]}_{key[1]}_s{key[2]}_{key[3]}"
        require(run_id in declared and declared[run_id]["input_sha256"] == row["input_sha256"], "CSV/manifest run or input mismatch")
        require(math.isclose(float(row["one_time_setup.wall_ms"])+float(row["operational_lifecycle.wall_ms"]),
                             float(row["full_lifecycle.wall_ms"]), abs_tol=.0002), "Lifecycle windows do not reconcile")
    cells = {(cell["family"], cell["name"]): cell for cell in summary["cells"]}
    require(len(cells) == len(summary["cells"]) == 13, "Expected nine synthetic and four workflow cells")
    synthetic = sorted((cell for cell in cells.values() if cell["family"] == "synthetic"),
                       key=lambda cell: (cell["config"]["support_size"], cell["config"]["release_update_ratio"]))
    workflow = [cells[("workflow", scenario)] for scenario in SCENARIOS]
    require({(cell["config"]["support_size"], cell["config"]["release_update_ratio"]) for cell in synthetic}
            == {(k, ratio) for k in (128, 512, 2048) for ratio in (.25, 1, 16)}, "Synthetic matrix is incomplete")
    visited = set()
    for cell in synthetic+workflow:
        seeds = cell["seeds"]
        require(len(seeds) == len(set(seeds)) == LIFECYCLE_SEEDS and set(cell["policy_means"]) == set(POLICIES), f"Expected {LIFECYCLE_SEEDS} paired seeds and all policies")
        require(set(cell["paired_delta_minus_baseline"]) == set(BASELINES), "Both baseline contrasts are required")
        for seed in seeds:
            matching = [rows[(cell["family"], cell["name"], seed, policy)] for policy in POLICIES]
            require(len({row["input_sha256"] for row in matching}) == 1, "Paired lifecycle inputs differ")
        for policy in POLICIES:
            group = [rows[(cell["family"], cell["name"], seed, policy)] for seed in seeds]
            visited.update((cell["family"], cell["name"], seed, policy) for seed in seeds)
            for metric, value in cell["policy_means"][policy].items():
                require(math.isclose(fmean(float(row[metric]) for row in group), finite(value), rel_tol=1e-9, abs_tol=1e-7),
                        f"CSV/summary mean mismatch: {cell['name']} {policy} {metric}")
        for baseline in BASELINES:
            for metric, stat in cell["paired_delta_minus_baseline"][baseline].items():
                expected = [float(rows[(cell["family"],cell["name"],seed,"adaptive_delta")][metric])
                            -float(rows[(cell["family"],cell["name"],seed,baseline)][metric]) for seed in seeds]
                require(stat["n_runs"] == len(stat["values"]) == LIFECYCLE_SEEDS and all(math.isclose(a,b,rel_tol=1e-9,abs_tol=1e-7)
                            for a,b in zip(expected, stat["values"])), "Stored paired differences do not match CSV")
                require(math.isclose(fmean(expected), finite(stat["mean"]), rel_tol=1e-9, abs_tol=1e-7), "Paired mean mismatch")
    require(visited == set(rows), "Unexpected or uncovered lifecycle CSV rows")
    return synthetic, workflow, manifest


def lifecycle_tables(synthetic, workflow):
    outputs = {}
    headers = [r"$|S|$", r"$R/U$", "Policy", r"\shortstack{Setup\\wall}", r"\shortstack{Oper.\\wall}",
               r"\shortstack{Full\\wall}", r"\shortstack{Oper.\\CPU}", r"\shortstack{Full\\CPU}", "Writer"]
    rows = []
    for i, cell in enumerate(synthetic):
        if i:
            rows.append(r"\addlinespace[2pt]")
        for j, policy in enumerate(POLICIES):
            rows.append([integer(cell["config"]["support_size"]) if j == 0 else "",
                         f"{cell['config']['release_update_ratio']:g}" if j == 0 else "", LABELS[policy]]
                        +[num(cell["policy_means"][policy][key]) for key in LIFECYCLE_METRICS])
    outputs["ready_lifecycle_totals"] = table(
        "Complete synthetic release-lifecycle means (ms), 30 independent runs per policy and cell.",
        "tab:ready-lifecycle-totals", "rrlrrrrrr", headers, rows,
        r"$R/U$ is the number of release attempts per admitted update. Each run has 64 releases; support size and update count vary. "
        r"Setup + operational wall time equals full wall time. CPU is current-process CPU. Writer is the sum of distinct operational writer transactions; "
        r"it is a nested component and is not added to elapsed or CPU time.")
    differences = []
    for baseline in BASELINES:
        rows = [[integer(cell["config"]["support_size"]), f"{cell['config']['release_update_ratio']:g}"]
                +[interval(cell["paired_delta_minus_baseline"][baseline][key], lifecycle=True) for key in DELTA_METRICS]
                for cell in synthetic]
        differences.append(table("Synthetic paired differences: adaptive delta minus "+LABELS[baseline]+" (ms).",
            "tab:ready-lifecycle-diff-"+baseline.replace("_","-"), "rrrrr",
            [r"$|S|$", r"$R/U$", r"$\Delta$ full wall", r"$\Delta$ operational wall", r"$\Delta$ writer"], rows,
            r"Each entry is the mean paired difference with its stored whole-run bootstrap 95\% interval below (30 pairs). "
            r"Negative values favour adaptive delta. These exploratory intervals do not correct for multiple comparisons; "
            r"an interval crossing zero does not establish a benefit."))
    outputs["ready_lifecycle_differences"] = "\n".join(differences)
    workflow_sections = []
    for measures, suffix, caption in ((LIFECYCLE_METRICS[:3], "wall", "Setup and elapsed time"),
                                     (LIFECYCLE_METRICS[3:], "cpu-writer", "CPU and writer time")):
        rows = []
        for i, cell in enumerate(workflow):
            if i:
                rows.append(r"\addlinespace[2pt]")
            for j, policy in enumerate(POLICIES):
                rows.append([SCENARIO_LABELS[cell["name"]] if j == 0 else "", LABELS[policy]]
                            +[num(cell["policy_means"][policy][key]) for key in measures])
        selected_headers = ["Setup wall", "Operational wall", "Full wall"] if suffix == "wall" else ["Operational CPU", "Full CPU", "Writer"]
        workflow_sections.append(table("Real GHCN report-release lifecycle: "+caption.lower()+" (ms), 30 runs per entry.",
            "tab:ready-workflow-"+suffix, "llrrr", ["Scenario", "Policy", *selected_headers], rows,
            "The same 20 actual report payloads and their declared supports are used. Upstream scientific ETL was completed before this measurement. "
            "Setup and operational windows are separate; writer time is an explanatory subset."))
    for baseline in BASELINES:
        rows = [[SCENARIO_LABELS[cell["name"]]]+[interval(cell["paired_delta_minus_baseline"][baseline][key], lifecycle=True)
                  for key in DELTA_METRICS[:2]] for cell in workflow]
        workflow_sections.append(table("Real-workflow paired differences: adaptive delta minus "+LABELS[baseline]+" (ms).",
            "tab:ready-workflow-diff-"+baseline.replace("_","-"), "lrr", ["Scenario", r"$\Delta$ full wall", r"$\Delta$ operational wall"], rows,
            r"Mean paired differences and stored whole-run bootstrap 95\% intervals; 30 pairs per scenario. "
            r"All four interventions and both full-validation baselines are retained, including intervals crossing zero."))
    outputs["ready_workflow_totals"] = "\n".join(workflow_sections)
    # Optional main-text table: generated but not inserted automatically.
    rows = [[integer(cell["config"]["support_size"]), f"{cell['config']['release_update_ratio']:g}"]
            +[num(cell["policy_means"][policy]["operational_lifecycle.wall_ms"]) for policy in POLICIES]
            for cell in synthetic]
    outputs["ready_main_lifecycle"] = table("Operational release-lifecycle wall time (ms), means of 30 runs.",
        "tab:ready-main-lifecycle", "rrrrr", [r"$|S|$", r"$R/U$", *[LABELS[p] for p in POLICIES]], rows,
        "Each run contains 64 releases and all intervening source updates. The supplement reports setup, full lifecycle, CPU, writer time, and both paired baseline comparisons.")
    return outputs


def continuous_input(reader, folder, count):
    data = reader.json(folder/"analysis/continuous_analysis.json")
    require(data["requested_run_count"] == data["run_count"] == data["valid_run_count"] == len(data["runs"]) == count,
            f"Expected {count} valid service runs: {folder}")
    require(data["invalid_or_failed_run_count"] == 0 and data["all_requested_runs_present"]
            and not data["missing_requested_runs"] and not data["unexpected_runs"], "Incomplete or failed service cohort")
    keys = {(row["config"]["name"], row["seed"], row["policy"]) for row in data["runs"]}
    require(len(keys) == count and all(row["analysis_status"] == "valid" and row["correctness_checks_passed"]
                                      for row in data["runs"]), "Duplicate or unaudited service run")
    return data


def retention_tables(reader, root):
    folder = root/"results/retention"
    data = continuous_input(reader, folder, 15)
    seeds = sorted({row["seed"] for row in data["runs"]})
    configs = {row["config"]["name"] for row in data["runs"]}
    require(len(seeds) == 5 and len(configs) == 1 and {row["policy"] for row in data["runs"]} == set(POLICIES), "Incomplete retention pairing")
    require(all(row["completion_latency_n"] >= 200 for row in data["runs"]), "P99 lacks enough successful arrivals")
    by_policy = {row["policy"]: row for row in data["summary"]}
    require(len(by_policy) == len(data["summary"]) == 3 and all(row["runs"] == 5 for row in by_policy.values()), "Retention summary seed count mismatch")
    paired = {row["reference"]: row for row in data["paired_differences"] if row["policy"] == "adaptive_delta"}
    require(set(paired) == set(BASELINES), "Retention requires both paired baseline comparisons")
    for seed in seeds:
        group = [row for row in data["runs"] if row["seed"] == seed]
        require(len(group) == 3 and len({row["common_input_sha256"] for row in group}) == 1, "Retention paired inputs differ")
    rows = [[LABELS[policy]]+[interval(by_policy[policy][metric], scale=scale, digits=digits)
                            for metric, scale, digits in zip(SERVICE_METRICS,SERVICE_SCALES,SERVICE_DIGITS)]
            for policy in POLICIES]
    headers = ["Policy", r"\shortstack{P95\\(ms)}", r"\shortstack{P99\\(ms)}", r"\shortstack{Goodput\\(/s)}",
               r"\shortstack{Validation\\($\mu$s)}", r"\shortstack{Refresh log\\($\mu$s)}"]
    config = data["runs"][0]["config"]
    sections = [table("Service with history eviction: means of five complete-run statistics and stored 95\\% intervals.",
        "tab:ready-retention-means", "lrrrrr", headers, rows,
        "The measured window is "+num(config["measurement_s"],0)+" s, with "+num(config["mutation_rate"],0)
        +" planned source updates/s and history capacity "+integer(config["history_limit"])+". "
        "P95/P99 summarize scheduled-arrival latency among successful measurement arrivals. Goodput counts completions inside the window. "
        "Validation and refresh-log times are nested components, not end-to-end service costs.")]
    rows = [[LABELS[baseline]]+[interval(paired[baseline][metric], scale=scale, digits=digits)
                              for metric, scale, digits in zip(SERVICE_METRICS,SERVICE_SCALES,SERVICE_DIGITS)]
            for baseline in BASELINES]
    sections.append(table("History-eviction service: adaptive delta minus each baseline, paired by seed.",
        "tab:ready-retention-paired", "lrrrrr", ["Baseline", *headers[1:]], rows,
        r"Mean paired differences with stored whole-run bootstrap 95\% intervals (five pairs). Units match the preceding table. "
        "Negative latency or component differences favour adaptive delta; positive goodput differences favour it."))
    observations, rows = [], []
    run_lookup = {(row["seed"],row["policy"]): row for row in data["runs"]}
    for seed in seeds:
        for policy in POLICIES:
            run = run_lookup[seed,policy]
            obs = reader.json(folder/run["run_id"]/"history_observation.json")
            require(obs["status"] == "passed" and obs["policy"] == policy and obs["history_limit"] == run["config"]["history_limit"], "History observation mismatch")
            require(obs["mutations"] > 3*obs["history_limit"], "Retention cohort did not cross three history capacities")
            if policy == "adaptive_delta":
                require(obs["retained_rows"] == obs["history_limit"] and obs["pruned_through"] == obs["mutations"]-obs["history_limit"], "Retained-history floor does not reconcile")
            else:
                require(obs["retained_rows"] == obs["pruned_through"] == 0, "Full baseline unexpectedly retains adaptive history")
            phases = obs["refresh_history_component"]
            phase_values = []
            for phase in ("before_limit", "after_limit"):
                item = phases[phase]
                require(item["n"] > 0 and math.isclose(item["mean_ms"]*item["n"],item["sum_ms"],rel_tol=1e-9,abs_tol=1e-7), "History phase summary mismatch")
                phase_values.append(num(item["mean_ms"]*1000)+" ("+integer(item["n"])+")")
            rows.append([str(seeds.index(seed)+1), LABELS[policy], integer(obs["mutations"]), integer(obs["history_limit"]),
                         integer(obs["retained_rows"]), integer(obs["pruned_through"]), *phase_values])
            observations.append({"seed": seed, "run_id": run["run_id"], **obs})
    sections.append(table("Per-seed history observations, measured from admitted mutation ordinals.",
        "tab:ready-retention-observations", "rlrrrrrr",
        ["Seed", "Policy", "Mutations", "Limit", "Retained", "Floor", r"\shortstack{Before limit\\$\mu$s ($n$)}", r"\shortstack{After limit\\$\mu$s ($n$)}"], rows,
        "Seeds 1--5 denote "+", ".join(map(str,seeds))+". The floor is the last pruned mutation ordinal. "
        "Phase entries report mean refresh-log time and refresh count; invalidations advance the ordinal but are excluded from these refresh-only means. "
        "The counts and limits are read from each run, not inferred from intended rates."))
    return "\n".join(sections), data, observations


def cleanup_table(reader, root):
    data = continuous_input(reader, root/"results/cleanup", 12)
    seeds = sorted({row["seed"] for row in data["runs"]})
    require(len(seeds) == 3 and all(row["policy"] == "adaptive_delta" for row in data["runs"]), "Cleanup requires three seeds and fixed adaptive policy")
    cells = {(row["config"]["cleanup_backlog"], row["config"]["cleanup_batch"], row["seed"]) for row in data["runs"]}
    require(cells == {(backlog,batch,seed) for backlog in (4096,16384) for batch in (32,None) for seed in seeds}, "Incomplete cleanup matrix")
    rows, records = [], []
    for run in sorted(data["runs"], key=lambda row:(row["config"]["cleanup_backlog"],row["config"]["cleanup_batch"] is None,row["seed"])):
        config = run["config"]
        require(run["healthy_phase_cohort_count"] == 8, "Cleanup healthy cohort is not the fixed eight arrivals")
        deleted, backlog = run["backlog_cleaned_before_final_drain"], config["cleanup_backlog"]
        require(0 <= deleted <= backlog, "Invalid cleanup deletion count")
        observed = run["backlog_cleanup_fully_observed_before_drain"]
        span = run["backlog_cleanup_elapsed_ms"]
        if observed:
            require(deleted == backlog and finite(span) >= 0, "Complete cleanup span is inconsistent")
            span_text = num(span,1)
        else:
            require(span is None, "Censored span must not be reported as a complete duration")
            span_text = r"\textit{cens.}"
        completed = run["healthy_phase_cohort_completed"]
        require(completed+run["healthy_phase_cohort_blocked"]+run["healthy_phase_cohort_incomplete"] == 8, "Healthy cohort outcomes do not reconcile")
        maximum = run["healthy_phase_latency_max_ms"]
        require((maximum is not None) == (completed > 0), "Healthy latency count mismatch")
        rows.append([integer(backlog), "32" if config["cleanup_batch"] == 32 else "All", str(seeds.index(run["seed"])+1),
                     num(run["backlog_cleanup_transaction_max_ms"],3), integer(deleted), span_text,
                     str(completed)+"/8", num(maximum,1) if maximum is not None else "---"])
        keys = ("run_id", "seed", "backlog_cleanup_transaction_max_ms", "backlog_cleaned_before_final_drain",
                "backlog_cleanup_fully_observed_before_drain", "backlog_cleanup_elapsed_ms", "healthy_phase_cohort_count",
                "healthy_phase_cohort_completed", "healthy_phase_cohort_blocked", "healthy_phase_cohort_incomplete", "healthy_phase_latency_max_ms")
        records.append({"backlog":backlog, "batch":config["cleanup_batch"], **{key:run[key] for key in keys}})
    text = table("Concurrent cleanup: every seed, backlog size and batch mode.", "tab:ready-cleanup-runs", "rrcrrrrr",
        ["Backlog", "Batch", "Seed", r"\shortstack{Max writer\\(ms)}", r"\shortstack{Deleted\\pre-drain}",
         r"\shortstack{Span\\(ms)}", r"\shortstack{Healthy\\completed}", r"\shortstack{Healthy max\\(ms)}"], rows,
        "Seeds 1--3 denote "+", ".join(map(str,seeds))+". The release policy is adaptive delta throughout. "
        "Batch 32 processes at most 32 candidates plus one lookahead; All drains without a configured batch bound. "
        "Writer maxima refer to backlog-cleanup transactions. Deleted counts exclude final drain. Span includes observed backlog RPC gaps, transport and waits; "
        r"\textit{cens.} means clearance was not fully observed before final drain and is not assigned a duration. "
        "Healthy maxima use completed tasks among the same eight predeclared arrivals; incomplete/blocked counts remain in the completion denominator. Three seeds are exploratory.")
    return text, data, records


def service_headlines(data):
    keys = ("settled", "unsafe_settlements", "duplicate_ledger_entries", "measurement_arrivals", "measurement_window_completed",
            "measurement_cohort_completed", "measurement_cohort_blocked", "measurement_cohort_incomplete", "published_output_count",
            "source_time_exposure_settlements", "conservative_stale_rejections", "transport_failures", "server_errors")
    return {"requested_runs":data["requested_run_count"], "valid_runs":data["valid_run_count"],
            "totals":{key:sum(run[key] for run in data["runs"]) for key in keys},
            "per_policy_totals":{policy:{key:sum(run[key] for run in data["runs"] if run["policy"] == policy) for key in keys}
                                 for policy in sorted({row["policy"] for row in data["runs"]})}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root = args.root.resolve()
    reader = Inputs(root)
    synthetic, workflow, manifest = lifecycle_inputs(reader, root)
    outputs = lifecycle_tables(synthetic, workflow)
    outputs["ready_retention_summary"], retention, observations = retention_tables(reader, root)
    outputs["ready_cleanup_runs"], cleanup, cleanup_records = cleanup_table(reader, root)
    condensed = lambda cell: {"family":cell["family"], "name":cell["name"], "config":cell["config"], "seeds":cell["seeds"],
        "policy_means":cell["policy_means"], "paired_delta_minus_baseline":{baseline:{key:stat for key,stat in
             cell["paired_delta_minus_baseline"][baseline].items() if key in DELTA_METRICS} for baseline in BASELINES}}
    numbers = {"status":"passed", "physical_hosts":manifest["physical_hosts"], "source_sha256":reader.hashes,
        "lifecycle":{"requested_runs":LIFECYCLE_RUNS,"valid_completed_runs":LIFECYCLE_RUNS,"synthetic_runs":9*3*LIFECYCLE_SEEDS,"workflow_runs":4*3*LIFECYCLE_SEEDS,
                     "synthetic":[condensed(cell) for cell in synthetic],"workflow":[condensed(cell) for cell in workflow]},
        "retention":{**service_headlines(retention), "summary":[{key:row[key] for key in ("policy","runs",*SERVICE_METRICS)} for row in retention["summary"]],
            "paired_differences":[{key:row[key] for key in ("policy","reference",*SERVICE_METRICS)} for row in retention["paired_differences"] if row["policy"] == "adaptive_delta"],
            "history_observations":observations},
        "cleanup":{**service_headlines(cleanup), "censored_spans":sum(not row["backlog_cleanup_fully_observed_before_drain"] for row in cleanup_records),
                   "runs":cleanup_records},
        "qualification":"Stored whole-run intervals are copied, never recomputed; setup/full/operational windows and nested writer costs remain distinct."}
    # All source validation above succeeds before any output is replaced.
    table_dir = root/"paper/tables"
    table_dir.mkdir(parents=True, exist_ok=True)
    provenance = "% Generated by ready_tables.py from finalized independently audited summaries.\n"
    provenance += "".join("% "+name+" SHA256 "+digest+"\n" for name,digest in sorted(reader.hashes.items()) if "history_observation" not in name)
    for name, body in outputs.items():
        (table_dir/(name+".tex")).write_text(provenance+body, encoding="utf-8")
    (root/"qa").mkdir(exist_ok=True)
    (root/"qa/final_numbers.json").write_text(json.dumps(numbers,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"status":"passed", "table_files":list(outputs), "lifecycle_runs":LIFECYCLE_RUNS, "retention_runs":15, "cleanup_runs":12,
                      "numbers":"qa/final_numbers.json"}),flush=True)


if __name__ == "__main__":
    main()
