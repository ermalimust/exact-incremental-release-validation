"""Postprocess completed Computing cohorts; never start experiments.

Read figure_contract_ready.txt before use. Run only after timed benchmarks stop.
All measured values come from explicitly supplied paths. A lifecycle directory
may contain both synthetic and workflow families; each figure selects its own
family and checks the complete suite inventory before selection.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import random
from pathlib import Path
import statistics
import sys

LIFECYCLE_SEEDS = 30  # paired seeds per lifecycle cell
POLICIES = ("full_sql", "guarded_full", "adaptive_delta")
LABELS = {"full_sql": "Indexed full", "guarded_full": "Guarded full",
          "adaptive_delta": "Adaptive delta"}
STYLES = {"full_sql": ("#0072B2", "-", "o"),
          "guarded_full": ("#B56B2C", "--", "s"),
          "adaptive_delta": ("#25846C", "-.", "^")}
SEED_MARKERS = ("o", "^", "s", "D", "v")
SCENARIOS = ("all_valid", "unrelated_refresh", "benign_shared_refresh",
             "baseline_withdrawal")
SCENARIO_LABELS = {"all_valid": "All valid",
                   "unrelated_refresh": "Unrelated refresh",
                   "benign_shared_refresh": "Shared refresh",
                   "baseline_withdrawal": "Baseline withdrawal"}
NUMERIC_METRICS = ("full_lifecycle.wall_ms", "full_lifecycle.cpu_ms",
                   "one_time_setup.wall_ms", "operational_lifecycle.wall_ms",
                   "operational_lifecycle.cpu_ms", "operational_writer_ms",
                   "settle_validation_ms", "refresh_history_ms")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def finite(value):
    result = float(value)
    require(math.isfinite(result), "Nonfinite measurement")
    return result


def close(left, right):
    return math.isclose(float(left), float(right), rel_tol=1e-9, abs_tol=1e-7)


def load_json(path, sources, label):
    raw = Path(path).read_bytes()
    sources[label] = {"file": Path(path).name,
                      "sha256": hashlib.sha256(raw).hexdigest()}
    return json.loads(raw)


def csv_rows(path, sources, label):
    raw = Path(path).read_bytes()
    sources[label] = {"file": Path(path).name,
                      "sha256": hashlib.sha256(raw).hexdigest()}
    return list(csv.DictReader(raw.decode("utf-8-sig").splitlines()))


def write_csv(path, rows):
    require(bool(rows), "Refusing an empty source-data CSV")
    with Path(path).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def quantile(values, q):
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    left, right = math.floor(position), math.ceil(position)
    return (ordered[left] if left == right else
            ordered[left] * (right - position) + ordered[right] * (position - left))


def paired_interval(values):
    require(len(values) == LIFECYCLE_SEEDS, f"Lifecycle figures require {LIFECYCLE_SEEDS} paired runs")
    # Independent re-implementation of the lifecycle driver's interval: exact
    # enumeration for at most five runs, otherwise 10,000 seeded resamples.
    if len(values) <= 5:
        means = [statistics.fmean(draw)
                 for draw in itertools.product(values, repeat=len(values))]
    else:
        rng = random.Random(20261109)
        means = [statistics.fmean(rng.choices(values, k=len(values)))
                 for _ in range(10000)]
    return statistics.fmean(values), quantile(means, .025), quantile(means, .975)


def lifecycle(root, family):
    sources = {}
    root = Path(root)
    manifest = load_json(root / "manifest.json", sources, "manifest")
    summary = load_json(root / "summary.json", sources, "paired_summary")
    raw = csv_rows(root / "run_totals.csv", sources, "run_totals")
    require(manifest.get("status") == "completed"
            and summary.get("status") == "passed", "Incomplete lifecycle suite")
    require(len(raw) == manifest["requested_runs"] == manifest["completed_runs"]
            == summary["completed_runs"] == len(manifest["runs"]),
            "Lifecycle inventory is incomplete")
    require(all(r["status"] == "completed" for r in manifest["runs"]),
            "Failed lifecycle run")
    require(len({r["run_id"] for r in manifest["runs"]}) == len(raw),
            "Duplicate lifecycle run identity")
    lookup = {}
    for row in raw:
        item = dict(row)
        item["seed"] = int(row["seed"])
        for metric in NUMERIC_METRICS:
            item[metric] = finite(row[metric])
            require(item[metric] >= 0, "Negative absolute lifecycle duration")
        require(close(item["one_time_setup.wall_ms"] +
                      item["operational_lifecycle.wall_ms"],
                      item["full_lifecycle.wall_ms"]),
                "Setup and operational wall windows do not partition full time")
        key = (item["family"], item["name"], item["seed"], item["policy"])
        require(key not in lookup, "Duplicate lifecycle cell/seed/policy")
        lookup[key] = item
    cells = [c for c in summary["cells"] if c["family"] == family]
    require(len({c["name"] for c in cells}) == len(cells), "Duplicate summary cell")
    if family == "synthetic":
        expected = {(k, ratio) for k in (128, 512, 2048) for ratio in (.25, 1, 16)}
        require(len(cells) == 9 and
                {(c["config"]["support_size"], c["config"]["release_update_ratio"])
                 for c in cells} == expected, "Expected all nine synthetic cells")
        cells.sort(key=lambda c: (c["config"]["support_size"],
                                   c["config"]["release_update_ratio"]))
        metrics = ("operational_lifecycle.wall_ms", "operational_writer_ms")
    else:
        require(len(cells) == 4 and {c["name"] for c in cells} == set(SCENARIOS),
                "Expected all four workflow cases")
        cells.sort(key=lambda c: SCENARIOS.index(c["name"]))
        metrics = ("full_lifecycle.wall_ms", "operational_lifecycle.wall_ms")
    selected_keys = {key for key in lookup if key[0] == family}
    expected_keys = set()
    source, aggregates = [], []
    all_seeds = None
    for cell in cells:
        seeds = sorted(cell["seeds"])
        require(len(seeds) == len(set(seeds)) == LIFECYCLE_SEEDS, f"Expected {LIFECYCLE_SEEDS} distinct seeds")
        if all_seeds is None:
            all_seeds = seeds
        require(seeds == all_seeds, "Seed identities differ between cells")
        for seed in seeds:
            keys = [(family, cell["name"], seed, p) for p in POLICIES]
            require(all(key in lookup for key in keys), "Incomplete policy pairing")
            expected_keys.update(keys)
            require(len({lookup[key]["input_sha256"] for key in keys}) == 1,
                    "Paired policies received different external inputs")
        for panel, metric in enumerate(metrics):
            differences = [lookup[(family, cell["name"], s, "adaptive_delta")][metric]
                           - lookup[(family, cell["name"], s, "guarded_full")][metric]
                           for s in seeds]
            center, low, high = paired_interval(differences)
            official = cell["paired_delta_minus_baseline"]["guarded_full"][metric]
            require(official["n_runs"] == LIFECYCLE_SEEDS and len(official["values"]) == LIFECYCLE_SEEDS
                    and all(close(a, b) for a, b in zip(differences, official["values"]))
                    and close(center, official["mean"])
                    and close(low, official["paired_bootstrap_95ci"][0])
                    and close(high, official["paired_bootstrap_95ci"][1]),
                    "Independent paired summary differs from lifecycle summary")
            label = (f'{cell["config"]["support_size"]} | '
                     f'{cell["config"]["release_update_ratio"]:g}'
                     if family == "synthetic" else SCENARIO_LABELS[cell["name"]])
            aggregates.append({"panel": panel, "metric": metric,
                               "cell": cell["name"], "label": label,
                               "n_seed_runs": LIFECYCLE_SEEDS, "mean_difference_ms": center,
                               "ci_low_ms": low, "ci_high_ms": high,
                               "guarded_absolute_mean_ms": statistics.fmean(
                                   lookup[(family, cell["name"], s, "guarded_full")][metric]
                                   for s in seeds),
                               "delta_absolute_mean_ms": statistics.fmean(
                                   lookup[(family, cell["name"], s, "adaptive_delta")][metric]
                                   for s in seeds)})
            for seed, difference in zip(seeds, differences):
                guarded = lookup[(family, cell["name"], seed, "guarded_full")]
                delta = lookup[(family, cell["name"], seed, "adaptive_delta")]
                source.append({"family": family, "panel": panel, "metric": metric,
                               "cell": cell["name"], "seed": seed,
                               "input_sha256": delta["input_sha256"],
                               "guarded_ms": guarded[metric], "delta_ms": delta[metric],
                               "paired_delta_minus_guarded_ms": difference})
    require(selected_keys == expected_keys, "Unexpected lifecycle rows selected")
    return source, aggregates, {
        "sources": sources, "selected_family": family, "paired_seeds": all_seeds,
        "selected_runs": len(selected_keys), "whole_suite_runs": len(raw),
        "statistical_unit": "complete independent run, paired by seed and input hash",
        "interval": "10,000 seeded whole-run bootstrap resamples (seed 20261109), "
                    "as in the lifecycle driver; 95% percentile interval; exploratory, no multiplicity correction",
        "difference": "adaptive delta minus guarded full; negative favors delta",
        "timing": "separately measured complete windows; no addition of nested components",
        "scientific_ETL_included": False}


def validated_continuous(path, expected):
    sources = {}
    data = load_json(path, sources, "continuous_analysis")
    require(all(data.get(k) == expected for k in
                ("run_count", "valid_run_count", "requested_run_count")),
            f"Expected all {expected} independently validated runs")
    require(data.get("invalid_or_failed_run_count") == 0
            and data.get("all_requested_runs_present") is True
            and not data.get("missing_requested_runs")
            and not data.get("unexpected_runs"), "Incomplete continuous cohort")
    require(len(data["runs"]) == expected and
            len({r["run_id"] for r in data["runs"]}) == expected,
            "Invalid continuous run inventory")
    require(all(r["analysis_status"] == "valid" and r["status"] == "completed"
                and r["correctness_checks_passed"] for r in data["runs"]),
            "Unvalidated continuous run")
    return data["runs"], {"sources": sources,
                          "analysis_source_sha256": data["analysis_source_sha256"]}


def retention(path, run_root):
    runs, audit = validated_continuous(path, 15)
    seeds = sorted({r["seed"] for r in runs})
    require(len(seeds) == 5, "Expected five retention seeds")
    require({(r["policy"], r["seed"]) for r in runs} ==
            {(p, s) for p in POLICIES for s in seeds}, "Retention pairing mismatch")
    source, summary, histories = [], [], []
    by_pair, input_hashes = {}, {}
    offered_rates, durations, warmups = set(), set(), set()
    for run in runs:
        cfg = run["config"]
        duration, warmup = cfg["measurement_s"], cfg["warmup_s"]
        require(duration == 120 and int(warmup) == warmup and warmup >= 1,
                "Expected a 120-second cohort with integral warmup")
        duration, warmup = int(duration), int(warmup)
        require(cfg["cleanup_backlog"] == 0, "Retention plot excludes cleanup backlog")
        require(run["measurement_end_ns"] - run["measurement_start_ns"] ==
                duration * 1_000_000_000 and
                run["measurement_start_ns"] - run["started_ns"] ==
                warmup * 1_000_000_000, "Unexpected measurement boundaries")
        input_hashes.setdefault(run["seed"], set()).add(run["common_input_sha256"])
        offered_rates.add(finite(cfg["arrival_rate"]))
        durations.add(duration)
        warmups.add(warmup)
        trace = run["measurement_trace"]
        require([r["second"] for r in trace] == list(range(duration + warmup)),
                "Missing warmup or measurement bins")
        complete, blocked = set(run["completed_effect_ids"]), set(run["blocked_effect_ids"])
        require(len(complete) == len(run["completed_effect_ids"]) and
                len(blocked) == len(run["blocked_effect_ids"]) and not complete & blocked,
                "Duplicated or conflicting terminal reply identities")
        cumulative = {"arrivals": 0, "completed": 0, "blocked": 0}
        items = []
        for entry in trace:
            require(all(type(entry[key]) is int and entry[key] >= 0 for key in cumulative),
                    "Negative or nonintegral event count")
            before = cumulative["arrivals"] - cumulative["completed"] - cumulative["blocked"]
            for key in cumulative:
                cumulative[key] += entry[key]
            after = cumulative["arrivals"] - cumulative["completed"] - cumulative["blocked"]
            require(after >= 0, "Terminal replies exceed scheduled arrivals")
            item = {"run_id": run["run_id"], "policy": run["policy"], "seed": run["seed"],
                    "phase": "warmup" if entry["second"] < warmup else "measurement",
                    "measurement_bin_start_s": entry["second"] - warmup,
                    "measurement_bin_end_s": entry["second"] - warmup + 1,
                    "arrivals": entry["arrivals"], "completed": entry["completed"],
                    "blocked": entry["blocked"], "outstanding_start": before,
                    "outstanding_end": after,
                    "common_input_sha256": run["common_input_sha256"]}
            source.append(item)
            if item["phase"] == "measurement":
                items.append(item)
        require(sum(r["arrivals"] for r in items) == run["measurement_arrivals"]
                and sum(r["completed"] for r in items) == run["measurement_window_completed"],
                "Trace disagrees with audited denominators")
        terminal = len(complete | blocked)
        require(cumulative["completed"] + cumulative["blocked"] <= terminal
                <= cumulative["arrivals"], "Terminal totals fail conservation")
        by_pair[(run["policy"], run["seed"])] = items
        history = load_json(Path(run_root) / run["run_id"] / "history_observation.json",
                            audit["sources"], "history:" + run["run_id"])
        require(history["status"] == "passed" and history["policy"] == run["policy"]
                and history["history_limit"] == cfg["history_limit"]
                and history["mutations"] > 3 * history["history_limit"],
                "Retention crossing not demonstrated by the run witness")
        if run["policy"] == "adaptive_delta":
            require(history["retained_rows"] == history["history_limit"]
                    and history["pruned_through"] ==
                    history["mutations"] - history["history_limit"],
                    "Adaptive pruning witness mismatch")
        else:
            require(history["retained_rows"] == history["pruned_through"] == 0,
                    "Unexpected retained history for a full baseline")
        histories.append({"run_id": run["run_id"], "policy": run["policy"],
                          "seed": run["seed"], "mutations": history["mutations"],
                          "history_limit": history["history_limit"],
                          "pruned_through": history["pruned_through"]})
    require(all(len(hashes) == 1 for hashes in input_hashes.values()),
            "Retention inputs are not paired")
    require(len(offered_rates) == len(durations) == len(warmups) == 1,
            "Retention configurations differ")
    for policy in POLICIES:
        for second in range(120):
            row = {"policy": policy, "measurement_bin_start_s": second,
                   "measurement_bin_end_s": second + 1, "n_seed_runs": 5}
            for metric in ("arrivals", "completed", "blocked",
                           "outstanding_start", "outstanding_end"):
                values = [by_pair[(policy, s)][second][metric] for s in seeds]
                row.update({metric + "_mean": statistics.fmean(values),
                            metric + "_min": min(values), metric + "_max": max(values)})
            summary.append(row)
    audit.update(paired_seeds=seeds, valid_runs=15, duration_s=120,
                 offered_per_s=next(iter(offered_rates)),
                 warmup_s=next(iter(warmups)), history_witnesses=histories,
                 band="pointwise seed minimum/maximum, not a confidence interval",
                 outstanding="cumulative arrivals minus successful and blocked terminal "
                             "replies; includes warmup carryover; not only a server queue",
                 scope="fixed offered load; measurement window excludes drain; "
                       "no capacity or steady-state inference")
    return source, summary, audit


def cleanup(path):
    runs, audit = validated_continuous(path, 12)
    seeds = sorted({r["seed"] for r in runs})
    require(len(seeds) == 3, "Expected three cleanup seeds")
    lookup, source = {}, []
    for run in runs:
        cfg = run["config"]
        backlog, batch = cfg["cleanup_backlog"], cfg["cleanup_batch"]
        require(run["policy"] == "adaptive_delta" and backlog in (4096, 16384)
                and batch in (32, None), "Unexpected cleanup stress configuration")
        key = (backlog, batch, run["seed"])
        require(key not in lookup, "Duplicate cleanup pairing")
        lookup[key] = run
        cleaned = run["backlog_cleaned_before_final_drain"]
        require(type(cleaned) is int and 0 <= cleaned <= backlog,
                "Invalid reclaimed-backlog denominator")
        hold = finite(run["backlog_cleanup_transaction_max_ms"])
        require(hold > 0, "Logarithmic writer-hold panel requires positive observations")
        source.append({"run_id": run["run_id"], "seed": run["seed"],
                       "backlog": backlog, "batch": "unbounded" if batch is None else "32",
                       "max_backlog_writer_ms": hold,
                       "reclaimed_before_final_drain": cleaned,
                       "reclaimed_fraction": cleaned / backlog,
                       "exogenous_input_sha256": run["exogenous_input_sha256"],
                       "healthy_phase_count": run["healthy_phase_cohort_count"],
                       "healthy_phase_completed": run["healthy_phase_cohort_completed"]})
    require(set(lookup) == {(k, b, s) for k in (4096, 16384)
                            for b in (32, None) for s in seeds},
            "Incomplete cleanup pairs")
    differences = []
    for backlog in (4096, 16384):
        for seed in seeds:
            bounded, unbounded = lookup[(backlog, 32, seed)], lookup[(backlog, None, seed)]
            require(bounded["exogenous_input_sha256"] ==
                    unbounded["exogenous_input_sha256"], "Cleanup inputs differ")
            differences.append({
                "backlog": backlog, "seed": seed,
                "bounded_minus_unbounded_max_writer_ms":
                    bounded["backlog_cleanup_transaction_max_ms"] -
                    unbounded["backlog_cleanup_transaction_max_ms"],
                "bounded_minus_unbounded_reclaimed_fraction":
                    (bounded["backlog_cleaned_before_final_drain"] -
                     unbounded["backlog_cleaned_before_final_drain"]) / backlog})
    source.sort(key=lambda r: (r["backlog"], r["batch"] == "unbounded", r["seed"]))
    audit.update(valid_runs=12, paired_seeds=seeds,
                 statistical_unit="one independent seed-specific run",
                 interval="none; all three paired runs shown",
                 writer_hold="maximum instrumented nonempty backlog cleanup transaction; "
                             "excludes lock acquisition wait and HTTP transport",
                 reclamation="initial backlog fraction cleaned before final drain",
                 scope="observations, not a time bound or general service-tail guarantee")
    return source, differences, audit


def plotting_runtime(dependencies):
    for path in reversed(dependencies):
        require(path.is_dir(), "Dependency directory is missing")
        sys.path.insert(0, str(path))
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("Python plotting requires matplotlib and its dependencies; "
                           "supply --deps or install them in the selected Python runtime") from exc
    matplotlib.rcParams.update({
        "font.family": "sans-serif", "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
        "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 9,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 9,
        "axes.linewidth": .65, "axes.spines.top": False, "axes.spines.right": False,
        "svg.fonttype": "none", "pdf.fonttype": 42, "text.usetex": False,
        "savefig.facecolor": "white"})
    return plt


def finish(fig, output, source_output, name, source, summary, audit, plt):
    from matplotlib.text import Text
    import matplotlib
    # Locator objects may create off-range ticks whose labels remain marked
    # visible although Matplotlib does not draw them. Freeze only in-range
    # major ticks so the canvas audit inspects the actual exported labels.
    for ax in fig.axes:
        for axis, bounds in ((ax.xaxis, ax.get_xlim()), (ax.yaxis, ax.get_ylim())):
            lower, upper = sorted(bounds)
            ticks = [value for value in axis.get_majorticklocs()
                     if lower <= value <= upper]
            axis.set_ticks(ticks)
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    texts = [artist for artist in fig.findobj(Text)
             if artist.get_visible() and artist.get_text().strip()]
    sizes = sorted({artist.get_fontsize() for artist in texts})
    require(min(sizes) >= 9, "Figure has text smaller than 9 pt")
    outside = []
    for artist in texts:
        bounds = artist.get_window_extent(renderer=renderer)
        if not (fig.bbox.contains(bounds.x0, bounds.y0) and
                fig.bbox.contains(bounds.x1, bounds.y1)):
            outside.append(artist.get_text())
    require(not outside, "Text outside fixed-size canvas: " + repr(outside))
    output.mkdir(parents=True, exist_ok=True)
    source_output.mkdir(parents=True, exist_ok=True)
    stem = output / name
    write_csv(source_output / (name + "_source.csv"), source)
    write_csv(source_output / (name + "_summary.csv"), summary)
    for extension, dpi in (("pdf", None), ("svg", None), ("png", 300), ("tiff", 600)):
        options = {} if dpi is None else {"dpi": dpi}
        if extension == "tiff":
            options["pil_kwargs"] = {"compression": "tiff_lzw"}
        fig.savefig(stem.with_suffix("." + extension), **options)
    preview = source_output / (name + "_preview.png")
    fig.savefig(preview, dpi=100)
    audit.update(status="exported_pending_visual_review", width_mm=122,
                 height_mm=float(fig.get_figheight() * 25.4), font_sizes_pt=sizes,
                 text_outside_canvas=outside, matplotlib_version=matplotlib.__version__,
                 plot_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 experiments_run=False, pdf_fonttype=42, svg_fonttype="none",
                 preview={"dpi": 100, "file": preview.name,
                          "sha256": hashlib.sha256(preview.read_bytes()).hexdigest()},
                 source_csv_sha256={kind: hashlib.sha256(
                     (source_output / (name + "_" + kind + ".csv")).read_bytes()).hexdigest()
                     for kind in ("source", "summary")},
                 outputs={suffix: hashlib.sha256(stem.with_suffix("." + suffix).read_bytes()).hexdigest()
                          for suffix in ("pdf", "svg", "png", "tiff")})
    (source_output / (name + "_audit.json")).write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    plt.close(fig)
    print(json.dumps({"figure": name, "status": audit["status"], "source_rows": len(source)}))


def forest(source, summary, family, plt):
    from matplotlib.ticker import MaxNLocator
    cost = family == "synthetic"
    height = 145 if cost else 108
    fig = plt.figure(figsize=(122 / 25.4, height / 25.4), facecolor="white")
    rectangles = ([.28, .58, .68, .31], [.28, .13, .68, .31]) if cost else (
        [.36, .59, .60, .25], [.36, .16, .60, .25])
    titles = ("Operational wall time", "Operational writer occupancy") if cost else (
        "Full release lifecycle", "Operational lifecycle")
    seeds = sorted({row["seed"] for row in source})
    for panel, (rectangle, title) in enumerate(zip(rectangles, titles)):
        ax = fig.add_axes(rectangle)
        rows = [row for row in summary if row["panel"] == panel]
        plotted = []
        for y, row in enumerate(rows):
            points = [p for p in source if p["panel"] == panel and p["cell"] == row["cell"]]
            points.sort(key=lambda p: p["seed"])
            for point in points:
                index = seeds.index(point["seed"])
                x = point["paired_delta_minus_guarded_ms"]
                plotted.append(x)
                offset = (index - (len(seeds) - 1) / 2) * (.5 / max(len(seeds) - 1, 1))
                ax.scatter(x, y + offset, s=6, marker="o", facecolors="none",
                           edgecolors="#9A9A9A", linewidths=.45, zorder=3)
            center, low, high = (row["mean_difference_ms"], row["ci_low_ms"], row["ci_high_ms"])
            plotted.extend((low, high))
            ax.errorbar(center, y, xerr=[[center - low], [high - center]],
                        fmt="D", color="#0072B2", ms=3.8, lw=1.1,
                        capsize=2.4, capthick=.8, zorder=4)
        ax.axvline(0, color="#555555", linestyle=(0, (2, 2)), lw=.8, zorder=1)
        low, high = min(0, min(plotted)), max(0, max(plotted))
        padding = max((high - low) * .1, .01)
        ax.set_xlim(low - padding, high + padding)
        ax.set_ylim(len(rows) - .45, -.55)
        ax.set_yticks(range(len(rows)), [row["label"] for row in rows])
        ax.set_xlabel("Delta − guarded (ms/run)", labelpad=4)
        ax.set_title(title, loc="left", pad=11, fontweight="bold")
        ax.xaxis.set_major_locator(MaxNLocator(nbins=5))
        ax.tick_params(length=2.5, width=.65)
        ax.grid(axis="x", color="#E3E3E3", linewidth=.4, zorder=0)
        fig.text(.03, rectangle[1] + rectangle[3] + .027, "ab"[panel],
                 weight="bold", fontsize=10)
        if cost:
            fig.text(.09, rectangle[1] + rectangle[3] + .027, "k | R/U", fontsize=9)
    fig.text(.03, .025, "Points: paired seeds; bars: 95% CI; <0 favors delta", fontsize=9)
    return fig


def draw_retention(summary, audit, plt):
    from matplotlib.lines import Line2D
    from matplotlib.ticker import MaxNLocator
    fig = plt.figure(figsize=(122 / 25.4, 110 / 25.4), facecolor="white")
    axes = [fig.add_axes([.17, .59, .79, .29]), fig.add_axes([.17, .14, .79, .29])]
    handles = []
    for policy in POLICIES:
        rows = [row for row in summary if row["policy"] == policy]
        color, style, marker = STYLES[policy]
        handles.append(Line2D([0], [0], color=color, linestyle=style, marker=marker,
                              markersize=3, lw=1.1, label=LABELS[policy]))
        x = [r["measurement_bin_start_s"] + .5 for r in rows]
        axes[0].fill_between(x, [r["completed_min"] for r in rows],
                             [r["completed_max"] for r in rows],
                             color=color, alpha=.1, linewidth=0)
        axes[0].plot(x, [r["completed_mean"] for r in rows], color=color,
                     linestyle=style, marker=marker, markevery=12, ms=2.3, lw=1)
        def boundaries(stat):
            return [rows[0]["outstanding_start_" + stat]] + [
                row["outstanding_end_" + stat] for row in rows]
        axes[1].fill_between(range(121), boundaries("min"), boundaries("max"),
                             color=color, alpha=.1, linewidth=0)
        axes[1].plot(range(121), boundaries("mean"), color=color,
                     linestyle=style, marker=marker, markevery=12, ms=2.3, lw=1)
    offered = audit["offered_per_s"]
    axes[0].axhline(offered, color="#666666", linestyle=(0, (1, 2)), lw=.7)
    axes[0].set_ylim(0, max(offered, max(r["completed_max"] for r in summary)) * 1.15)
    axes[0].text(119, offered + axes[0].get_ylim()[1] * .025,
                 f"{offered:g} offered/s", ha="right", va="bottom", fontsize=9)
    axes[1].set_ylim(0, max(1, max(r["outstanding_end_max"] for r in summary)) * 1.12)
    for ax, letter, title in zip(axes, ("a", "b"),
                                 ("Completed replies per second", "Unfinished scheduled tasks")):
        ax.set_xlim(0, 120)
        ax.set_xticks((0, 30, 60, 90, 120))
        ax.yaxis.set_major_locator(MaxNLocator(nbins=5, integer=True))
        ax.set_title(title, loc="left", pad=9)
        ax.text(-.17, 1.09, letter, transform=ax.transAxes, fontsize=10, weight="bold")
        ax.tick_params(length=2.5, width=.65)
        ax.grid(axis="y", color="#DDDDDD", lw=.4)
    axes[0].set_ylabel("Successful replies / s")
    axes[1].set_ylabel("Unfinished tasks")
    axes[1].set_xlabel("Measurement time (s)", labelpad=4)
    fig.legend(handles=handles, ncol=3, loc="upper center", bbox_to_anchor=(.52, .995),
               frameon=False, handlelength=1.6, columnspacing=.7, handletextpad=.4)
    fig.text(.17, .025, "Mean and min–max of five runs; bands are not CIs", fontsize=9)
    return fig


def draw_cleanup(source, audit, plt):
    from matplotlib.lines import Line2D
    from matplotlib.ticker import NullFormatter, PercentFormatter
    fig = plt.figure(figsize=(122 / 25.4, 112 / 25.4), facecolor="white")
    axes = [fig.add_axes([.20, .60, .76, .25]), fig.add_axes([.20, .16, .76, .25])]
    colors = ("#0072B2", "#B56B2C", "#25846C")
    seeds = audit["paired_seeds"]
    lookup = {(r["backlog"], r["batch"], r["seed"]): r for r in source}
    for index, seed in enumerate(seeds):
        for backlog_index, backlog in enumerate((4096, 16384)):
            rows = [lookup[(backlog, batch, seed)] for batch in ("32", "unbounded")]
            x = [2 * backlog_index + j + (index - 1) * .065 for j in (0, 1)]
            for ax, metric in zip(axes, ("max_backlog_writer_ms", "reclaimed_fraction")):
                ax.plot(x, [r[metric] for r in rows], marker=SEED_MARKERS[index],
                        color=colors[index], lw=.7, ms=4, markerfacecolor="white",
                        markeredgewidth=.9, zorder=3)
    axes[0].set_yscale("log")
    axes[0].yaxis.set_minor_formatter(NullFormatter())
    axes[0].set_ylabel("Max. writer hold (ms)")
    axes[1].set_ylabel("Backlog reclaimed")
    axes[1].set_ylim(-.03, 1.07)
    axes[1].set_yticks((0, .25, .5, .75, 1))
    axes[1].yaxis.set_major_formatter(PercentFormatter(xmax=1, decimals=0))
    for ax, letter, title in zip(axes, ("a", "b"),
                                 ("Cleanup transaction occupancy", "Reclaimed before final drain")):
        ax.set_xlim(-.4, 3.4)
        ax.set_xticks(range(4), ("4096\nB=32", "4096\nUnbounded",
                                 "16384\nB=32", "16384\nUnbounded"))
        ax.set_title(title, loc="left", pad=10)
        ax.text(-.20, 1.12, letter, transform=ax.transAxes, weight="bold", fontsize=10)
        ax.tick_params(length=2.5, width=.65)
        ax.grid(axis="y", color="#DDDDDD", lw=.4)
        ax.axvline(1.5, color="#DDDDDD", lw=.6)
    handles = [Line2D([0], [0], color=colors[i], marker=SEED_MARKERS[i],
                       markerfacecolor="white", lw=.7, ms=4, label=f"Seed {i + 1}")
               for i in range(3)]
    fig.legend(handles=handles, ncol=3, loc="upper center", bbox_to_anchor=(.55, .995),
               frameon=False, handlelength=1.8, columnspacing=1)
    fig.text(.20, .025, "Paired modes; each marker is one complete run", fontsize=9)
    return fig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic", type=Path, help="Completed lifecycle directory")
    parser.add_argument("--workflow", type=Path, help="May be the same lifecycle directory")
    parser.add_argument("--retention", type=Path, help="Validated continuous_analysis.json")
    parser.add_argument("--retention-runs", type=Path, help="Raw run root with history witnesses")
    parser.add_argument("--cleanup", type=Path, help="Validated cleanup continuous_analysis.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-output", type=Path, help="CSV/audit directory; defaults to output")
    parser.add_argument("--deps", type=Path, action="append", default=[])
    args = parser.parse_args()
    if not any((args.synthetic, args.workflow, args.retention, args.cleanup)):
        parser.error("Select at least one completed cohort")
    if args.retention and not args.retention_runs:
        parser.error("--retention requires --retention-runs")
    plt = plotting_runtime(args.deps)
    source_output = args.source_output or args.output
    for root, family, name in ((args.synthetic, "synthetic", "ready_lifecycle"),
                               (args.workflow, "workflow", "ready_workflow")):
        if root:
            source, summary, audit = lifecycle(root, family)
            fig = forest(source, summary, family, plt)
            finish(fig, args.output, source_output, name, source, summary, audit, plt)
    if args.retention:
        source, summary, audit = retention(args.retention, args.retention_runs)
        fig = draw_retention(summary, audit, plt)
        finish(fig, args.output, source_output, "ready_retention", source, summary, audit, plt)
    if args.cleanup:
        source, summary, audit = cleanup(args.cleanup)
        fig = draw_cleanup(source, audit, plt)
        finish(fig, args.output, source_output, "ready_cleanup", source, summary, audit, plt)


if __name__ == "__main__":
    main()
