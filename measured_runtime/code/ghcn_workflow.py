"""Real NOAA GHCN-Daily ETL with generation-bound, schema-checked lineage.

All scientific transforms read through this adapter. This is a trusted workflow
adapter, not a detector of undeclared dependencies in arbitrary external code.
The case study uses public US station data and author-controlled withdrawal of
a derived baseline; it does not claim NOAA actually revoked any observation.
"""
from __future__ import annotations

import argparse
import calendar
import csv
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import time
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor

STATIONS = ("USW00094728", "USW00023174", "USW00094846")
FIRST_YEAR, BASELINE_END, LAST_YEAR = 1991, 2020, 2025
ELEMENTS = ("PRCP", "TMAX", "TMIN")
ROOT = Path(__file__).resolve().parents[1]
DATA_URL = "https://www.ncei.noaa.gov/pub/data/ghcn/daily/"
SCHEMA_VERSION = "ghcn-etl-v2"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def download_bytes(url):
    """Bounded parallel byte ranges avoid a slow large-file transfer.

    Every chunk is tied to the same ETag; range and length checks prevent
    accidentally combining different source versions or partial responses.
    """
    headers = {"User-Agent": "WASF-reproducibility/1.0"}
    with urlopen(Request(url, method="HEAD", headers=headers), timeout=45) as response:
        metadata = dict(response.headers)
        length = int(response.headers["Content-Length"])
        etag = response.headers.get("ETag")
        modified = response.headers.get("Last-Modified")
    if length < 200000 or not etag:
        with urlopen(Request(url, headers=headers), timeout=60) as response:
            content = response.read()
        if len(content) != length:
            raise ValueError("source byte length changed")
        return content, modified, etag
    chunks = [(start, min(start + 262143, length - 1)) for start in range(0, length, 262144)]
    def fetch(bounds):
        start, end = bounds
        request_headers = {**headers, "Range": f"bytes={start}-{end}", "If-Range": etag}
        with urlopen(Request(url, headers=request_headers), timeout=60) as response:
            if response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{end}/{length}":
                raise ValueError("source range/version response mismatch")
            if response.headers.get("ETag") != etag:
                raise ValueError("source ETag changed during download")
            content = response.read()
        if len(content) != end - start + 1:
            raise ValueError("partial range download")
        return content
    with ThreadPoolExecutor(max_workers=8) as pool:
        pieces = list(pool.map(fetch, chunks))
    return b"".join(pieces), modified, etag


def download_sources(destination):
    """Freeze exact public bytes; never silently replace an existing snapshot."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "source_manifest.json"
    if manifest_path.exists():
        manifest = read_json(manifest_path)
        if set(manifest["stations"]) != set(STATIONS):
            raise ValueError("source snapshot does not match configured stations")
        for item in manifest["files"]:
            if sha((destination / item["path"]).read_bytes()) != item["sha256"]:
                raise ValueError("downloaded source hash mismatch")
        return manifest
    names = ["readme.txt", "ghcnd-version.txt"]
    names += [f"all/{station}.dly" for station in STATIONS]
    names.append("ghcnd-stations.txt")
    progress_path = destination / "download_progress.json"
    progress = read_json(progress_path) if progress_path.exists() else {}
    records = []
    for remote in names:
        url = DATA_URL + remote
        relative = "raw/" + remote.rsplit("/", 1)[-1]
        target = destination / relative
        if url in progress and target.exists() and sha(target.read_bytes()) == progress[url]["sha256"]:
            records.append(progress[url])
            continue
        content, modified, etag = download_bytes(url)
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(content)
        records.append({"url": url, "path": relative, "sha256": sha(content),
                        "bytes": len(content), "last_modified": modified, "etag": etag,
                        "downloaded_utc": datetime.now(timezone.utc).isoformat()})
        progress[url] = records[-1]
        write_json(progress_path, progress)
        print(json.dumps({"downloaded": relative, "bytes": len(content), "sha256": sha(content)}), flush=True)
    stations = {}
    for line in (destination / "raw/ghcnd-stations.txt").read_text(encoding="utf-8").splitlines():
        if line[:11] in STATIONS:
            stations[line[:11]] = {"latitude": float(line[12:20]), "longitude": float(line[21:30]),
                                   "elevation_m": float(line[31:37]), "name": line[41:71].strip(),
                                   "original_record": line}
    if set(stations) != set(STATIONS):
        raise ValueError("selected stations missing in official station inventory")
    manifest = {"dataset": "NOAA GHCN-Daily, Version 3", "doi": "10.7289/V5D21VHZ",
                "version_text": (destination / "raw/ghcnd-version.txt").read_text().strip(),
                "files": records, "stations": stations, "period_used": [FIRST_YEAR, LAST_YEAR],
                "license": "US NOAA government data, public domain; attribution retained",
                "license_source": "https://www.noaa.gov/office-education/outreach-communication/faq",
                "dataset_terms": "https://www.ncei.noaa.gov/metadata/geoportal/rest/metadata/item/gov.noaa.ncdc:C00861/html",
                "derivative_notice": "All processed outputs are author-created derivatives, not official NOAA products."}
    write_json(manifest_path, manifest)
    return manifest


def required_roles(operation, parameters):
    """Closed schemas reject missing/extraneous parents known to this adapter."""
    if operation in ("source", "policy"):
        return []
    if operation == "parse_year":
        return ["raw_station", "format_policy"]
    if operation == "quality_filter":
        return ["parsed", "quality_policy"]
    if operation == "monthly_statistics":
        return ["quality_rows", "aggregation_policy"]
    if operation == "baseline":
        return [f"monthlies:{year}" for year in range(FIRST_YEAR, BASELINE_END + 1)] + ["baseline_policy"]
    if operation == "station_report":
        return ["monthlies", "baseline", "report_policy"]
    if operation == "cross_station_report":
        return [f"station_report:{station}" for station in STATIONS] + ["report_policy"]
    raise ValueError("unknown workflow step schema")


def generation_record(record):
    return {key: record[key] for key in ("artifact_id", "operation", "schema_version", "implementation_sha256", "parameters", "inputs", "sha256")}


class Builder:
    def __init__(self, output):
        self.root = Path(output)
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifacts = {}
        self.execution_reads = []
        self.implementation_sha256 = sha(Path(__file__).read_bytes())

    def add(self, artifact_id, operation, parameters, input_roles, transform):
        if artifact_id in self.artifacts:
            raise ValueError("duplicate artifact id")
        if set(input_roles) != set(required_roles(operation, parameters)):
            raise ValueError("step input schema mismatch")
        inputs, values = [], {}
        for role, parent_id in sorted(input_roles.items()):
            parent = self.artifacts[parent_id]
            raw = (self.root / parent["path"]).read_bytes()
            if sha(raw) != parent["sha256"]:
                raise ValueError("input content hash mismatch")
            inputs.append({"role": role, "artifact_id": parent_id,
                           "generation": parent["generation"], "sha256": parent["sha256"]})
            values[role] = raw
            self.execution_reads.append({"consumer": artifact_id, "role": role,
                                         "producer": parent_id, "generation": parent["generation"],
                                         "sha256": parent["sha256"]})
        started = time.perf_counter_ns()
        content = transform(values)
        elapsed = time.perf_counter_ns() - started
        if not isinstance(content, bytes):
            content = canonical(content)
        path = "artifacts/" + artifact_id.replace(":", "_") + ".dat"
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        record = {"artifact_id": artifact_id, "operation": operation, "schema_version": SCHEMA_VERSION,
                  "implementation_sha256": self.implementation_sha256,
                  "parameters": parameters, "inputs": inputs, "path": path,
                  "sha256": sha(content), "bytes": len(content), "transform_ns": elapsed}
        record["generation"] = sha(canonical(generation_record(record)))
        self.artifacts[artifact_id] = record
        return artifact_id


def csv_bytes(rows, fields):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def parse_year(raw, year, station):
    rows = []
    for line in raw.decode("ascii").splitlines():
        if len(line) != 269:
            raise ValueError("bad GHCN fixed-width record")
        if line[:11] != station:
            raise ValueError("station identity mismatch")
        if int(line[11:15]) != year or line[17:21] not in ELEMENTS:
            continue
        month = int(line[15:17])
        for day in range(1, calendar.monthrange(year, month)[1] + 1):
            start = 21 + 8 * (day - 1)
            rows.append({"date": f"{year:04d}-{month:02d}-{day:02d}", "element": line[17:21],
                         "value_tenths": int(line[start:start + 5]), "mflag": line[start + 5].strip(),
                         "qflag": line[start + 6].strip(), "sflag": line[start + 7].strip()})
    rows.sort(key=lambda row: (row["date"], row["element"]))
    if len({(r["date"], r["element"]) for r in rows}) != len(rows):
        raise ValueError("duplicate daily observation")
    return csv_bytes(rows, ("date", "element", "value_tenths", "mflag", "qflag", "sflag"))


def quality_filter(raw, policy):
    rows = list(csv.DictReader(io.StringIO(raw.decode())))
    by_day = {}
    for row in rows:
        value = int(row["value_tenths"])
        valid = value != policy["missing_value"] and row["qflag"] in policy["accepted_qflags"]
        if row["element"] == "PRCP" and value < 0:
            valid = False
        row["accepted"] = int(valid)
        by_day.setdefault(row["date"], {})[row["element"]] = row
    for daily in by_day.values():
        low, high = daily.get("TMIN"), daily.get("TMAX")
        if low and high and low["accepted"] and high["accepted"]:
            if int(low["value_tenths"]) > int(high["value_tenths"]):
                low["accepted"] = high["accepted"] = 0
    return csv_bytes(rows, ("date", "element", "value_tenths", "mflag", "qflag", "sflag", "accepted"))


def ratio(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def fraction(value):
    return Fraction(value["numerator"], value["denominator"])


def monthly_statistics(raw, year, policy):
    by_day = {}
    for row in csv.DictReader(io.StringIO(raw.decode())):
        if row["accepted"] == "1":
            by_day.setdefault(row["date"], {})[row["element"]] = int(row["value_tenths"])
    months = []
    for month in range(1, 13):
        daily = [v for d, v in by_day.items() if int(d[5:7]) == month]
        pairs = [(v["TMIN"], v["TMAX"]) for v in daily if "TMIN" in v and "TMAX" in v]
        rain = [v["PRCP"] for v in daily if "PRCP" in v]
        required = (calendar.monthrange(year, month)[1] * policy["coverage_numerator"] + policy["coverage_denominator"] - 1) // policy["coverage_denominator"]
        months.append({"month": month, "paired_temperature_days": len(pairs), "precipitation_days": len(rain),
                       "required_days": required, "temperature_eligible": len(pairs) >= required,
                       "temperature_mean_c": ratio(Fraction(sum(a + b for a, b in pairs), 20 * len(pairs))) if pairs else None,
                       "precipitation_total_mm": ratio(Fraction(sum(rain), 10)),
                       "precipitation_eligible": len(rain) >= required})
    return {"year": year, "months": months}


def baseline(values, policy):
    output = []
    for month in range(1, 13):
        eligible = [year["months"][month - 1] for year in values if year["months"][month - 1]["temperature_eligible"]]
        mean = sum((fraction(item["temperature_mean_c"]) for item in eligible), Fraction()) / len(eligible) if eligible else None
        output.append({"month": month, "eligible_years": len(eligible),
                       "baseline_eligible": len(eligible) >= policy["minimum_eligible_years"],
                       "temperature_mean_c": ratio(mean) if mean is not None else None})
    return {"first_year": FIRST_YEAR, "last_year": BASELINE_END, "months": output}


def station_report(current, reference, station, policy):
    months = []
    for actual, normal in zip(current["months"], reference["months"]):
        available = actual["temperature_eligible"] and normal["baseline_eligible"]
        delta = fraction(actual["temperature_mean_c"]) - fraction(normal["temperature_mean_c"]) if available else None
        months.append({"month": actual["month"], "eligible": available,
                       "temperature_anomaly_c": ratio(delta) if delta is not None else None,
                       "temperature_mean_c": actual["temperature_mean_c"],
                       "paired_temperature_days": actual["paired_temperature_days"],
                       "precipitation_total_mm": actual["precipitation_total_mm"],
                       "precipitation_eligible": actual["precipitation_eligible"]})
    eligible = [fraction(item["temperature_anomaly_c"]) for item in months if item["eligible"]]
    return {"station": station, "year": current["year"], "baseline": [FIRST_YEAR, BASELINE_END],
            "months": months, "eligible_months": len(eligible),
            "annual_mean_anomaly_c": ratio(sum(eligible, Fraction()) / len(eligible)) if len(eligible) >= policy["annual_minimum_months"] else None,
            "interpretation": "Descriptive station summary; not homogenized climate attribution."}


def cross_station_report(reports, year):
    return {"year": year, "station_reports": reports,
            "eligible_station_count": sum(report["annual_mean_anomaly_c"] is not None for report in reports),
            "interpretation": "Selected station reports; no spatial interpolation or area-weighted climate inference."}


def validate_manifests(manifest, root):
    root = Path(root).resolve()
    artifacts = manifest["artifacts"]
    read_set = {}
    for event in manifest["execution_reads"]:
        read_set.setdefault(event["consumer"], []).append({"role": event["role"], "artifact_id": event["producer"],
                                                          "generation": event["generation"], "sha256": event["sha256"]})
    visiting, seen = set(), set()
    def visit(aid):
        if aid in visiting:
            raise ValueError("lineage cycle")
        if aid in seen:
            return
        visiting.add(aid)
        record = artifacts[aid]
        if record["artifact_id"] != aid or record["schema_version"] != SCHEMA_VERSION:
            raise ValueError("artifact identity or schema mismatch")
        if "adapter_code_sha256" in manifest and record["implementation_sha256"] != manifest["adapter_code_sha256"]:
            raise ValueError("artifact implementation identity mismatch")
        roles = [item["role"] for item in record["inputs"]]
        if len(set(roles)) != len(roles) or set(roles) != set(required_roles(record["operation"], record["parameters"])):
            raise ValueError("required input missing or duplicated")
        if sorted(record["inputs"], key=lambda x: x["role"]) != sorted(read_set.get(aid, []), key=lambda x: x["role"]):
            raise ValueError("manifest differs from recorded execution read set")
        path = (root / record["path"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("artifact path escapes workflow root")
        if sha(path.read_bytes()) != record["sha256"]:
            raise ValueError("output content hash mismatch")
        if sha(canonical(generation_record(record))) != record["generation"]:
            raise ValueError("artifact generation mismatch")
        for item in record["inputs"]:
            parent = artifacts[item["artifact_id"]]
            if (item["generation"], item["sha256"]) != (parent["generation"], parent["sha256"]):
                raise ValueError("parent generation or content hash mismatch")
            visit(item["artifact_id"])
        visiting.remove(aid)
        seen.add(aid)
    for aid in artifacts:
        visit(aid)
    return {"artifacts_verified": len(seen), "read_events_verified": len(manifest["execution_reads"])}


def compile_workload(manifest, root):
    validate_manifests(manifest, root)
    root = Path(root)
    artifacts = manifest["artifacts"]
    # Generation is part of the gateway identity. A new manifest generation
    # cannot silently replace an already issued contract's support subject.
    subjects = {aid: aid + "@" + record["generation"] for aid, record in artifacts.items()}
    registry = {"artifact_parents": {}, "artifact_obligations": {}, "effect_artifacts": {}, "effect_obligations": {}}
    for aid, record in artifacts.items():
        registry["artifact_parents"][subjects[aid]] = [subjects[item["artifact_id"]] for item in record["inputs"]]
        if record["operation"] == "policy":
            registry["artifact_obligations"][subjects[aid]] = ["author_policy_acceptance:" + aid]
    effects = []
    support_sizes, depths = [], []
    def ancestors(aid):
        result = {aid}
        depth = 1
        for item in artifacts[aid]["inputs"]:
            parent_set, parent_depth = ancestors(item["artifact_id"])
            result.update(parent_set)
            depth = max(depth, parent_depth + 1)
        return result, depth
    for aid in manifest["release_artifacts"]:
        record = artifacts[aid]
        effect_id = "publish:" + aid
        registry["effect_artifacts"][effect_id] = [subjects[aid]]
        registry["effect_obligations"][effect_id] = ["author_release_approval:" + aid]
        result = json.loads((root / record["path"]).read_bytes())
        payload = {"artifact_id": aid, "generation": record["generation"], "content_sha256": record["sha256"], "result": result}
        effects.append({"effect_id": effect_id, "payer": "research_budget", "recipient": "publication_sink", "amount": 1,
                        "payload": payload, "artifact_path": record["path"], "generation": record["generation"]})
        closed, depth = ancestors(aid)
        support_sizes.append(len(closed) + sum(artifacts[x]["operation"] == "policy" for x in closed) + 1)
        depths.append(depth)
    target = f"baseline:{STATIONS[0]}"
    return {"schema_version": 2, "case": "ghcn_real_data", "registry": registry, "effects": effects,
            "accounts": {"research_budget": len(effects) * 10, "publication_sink": 0}, "expires_at": 4102444800.0,
            "stage_at_bootstrap": False, "manifest_sha256": sha(canonical(manifest)), "physical_hosts": 1,
            "dataset": "NOAA GHCN-Daily", "derived_outputs_are_official_noaa_products": False,
            "support_size_range": [min(support_sizes), max(support_sizes)], "lineage_depth_range": [min(depths), max(depths)],
            "controlled_revocation": {"kind": "invalidate", "subject_id": "a:" + subjects[target],
                                      "artifact_id": target, "origin": "author-controlled withdrawal of a derived baseline; not a NOAA event"}}


def run_workflow(data_root, output):
    data_root, output = Path(data_root), Path(output)
    if (output / "workflow_manifest.json").exists():
        raise FileExistsError("refusing to overwrite completed workflow")
    source_manifest = read_json(data_root / "source_manifest.json")
    for item in source_manifest["files"]:
        if sha((data_root / item["path"]).read_bytes()) != item["sha256"]:
            raise ValueError("frozen source integrity mismatch")
    builder = Builder(output)
    policies = {
        "format": {"layout": "GHCN-Daily 269-character records", "elements": list(ELEMENTS), "units": "integer tenths", "missing": -9999},
        "quality": {"missing_value": -9999, "accepted_qflags": [""], "temperature_order": "TMIN <= TMAX", "precipitation_nonnegative": True},
        "aggregation": {"coverage_numerator": 9, "coverage_denominator": 10, "temperature": "mean of paired daily (TMIN+TMAX)/2"},
        "baseline": {"first_year": FIRST_YEAR, "last_year": BASELINE_END, "minimum_eligible_years": 25, "weighting": "equal eligible monthly means"},
        "report": {"annual_minimum_months": 12, "weighting": "equal monthly anomalies"}}
    for name, content in policies.items():
        builder.add("policy:" + name, "policy", {"name": name}, {}, lambda _, c=content: c)
    releases = []
    count_parsed = count_accepted = 0
    for station in STATIONS:
        raw_id = "source:" + station
        builder.add(raw_id, "source", {"station": station, "source_manifest_sha256": sha(canonical(source_manifest))}, {},
                    lambda _, s=station: (data_root / "raw" / (s + ".dly")).read_bytes())
        for year in range(FIRST_YEAR, LAST_YEAR + 1):
            parsed_id = f"parsed:{station}:{year}"
            builder.add(parsed_id, "parse_year", {"station": station, "year": year},
                        {"raw_station": raw_id, "format_policy": "policy:format"},
                        lambda inp, y=year, s=station: parse_year(inp["raw_station"], y, s))
            qc_id = f"quality:{station}:{year}"
            builder.add(qc_id, "quality_filter", {"station": station, "year": year},
                        {"parsed": parsed_id, "quality_policy": "policy:quality"},
                        lambda inp: quality_filter(inp["parsed"], json.loads(inp["quality_policy"])))
            rows = list(csv.DictReader(io.StringIO((output / builder.artifacts[qc_id]["path"]).read_text())))
            count_parsed += len(rows)
            count_accepted += sum(row["accepted"] == "1" for row in rows)
            builder.add(f"monthly:{station}:{year}", "monthly_statistics", {"station": station, "year": year},
                        {"quality_rows": qc_id, "aggregation_policy": "policy:aggregation"},
                        lambda inp, y=year: monthly_statistics(inp["quality_rows"], y, json.loads(inp["aggregation_policy"])))
        baseline_id = f"baseline:{station}"
        parents = {f"monthlies:{year}": f"monthly:{station}:{year}" for year in range(FIRST_YEAR, BASELINE_END + 1)}
        parents["baseline_policy"] = "policy:baseline"
        builder.add(baseline_id, "baseline", {"station": station}, parents,
                    lambda inp: baseline([json.loads(inp[f"monthlies:{year}"]) for year in range(FIRST_YEAR, BASELINE_END + 1)], json.loads(inp["baseline_policy"])))
        for year in range(BASELINE_END + 1, LAST_YEAR + 1):
            aid = f"report:{station}:{year}"
            builder.add(aid, "station_report", {"station": station, "year": year},
                        {"monthlies": f"monthly:{station}:{year}", "baseline": baseline_id, "report_policy": "policy:report"},
                        lambda inp, s=station: station_report(json.loads(inp["monthlies"]), json.loads(inp["baseline"]), s, json.loads(inp["report_policy"])))
            releases.append(aid)
    for year in range(BASELINE_END + 1, LAST_YEAR + 1):
        aid = f"cross_report:{year}"
        parents = {f"station_report:{station}": f"report:{station}:{year}" for station in STATIONS}
        parents["report_policy"] = "policy:report"
        builder.add(aid, "cross_station_report", {"year": year}, parents,
                    lambda inp, y=year: cross_station_report([json.loads(inp[f"station_report:{station}"]) for station in STATIONS], y))
        releases.append(aid)
    manifest = {"schema_version": SCHEMA_VERSION, "dataset_source_manifest_sha256": sha(canonical(source_manifest)),
                "adapter_code_sha256": sha(Path(__file__).read_bytes()), "stations": list(STATIONS),
                "period": [FIRST_YEAR, LAST_YEAR], "baseline_period": [FIRST_YEAR, BASELINE_END],
                "artifacts": builder.artifacts, "execution_reads": builder.execution_reads,
                "release_artifacts": releases, "parsed_observations": count_parsed, "accepted_observations": count_accepted,
                "trust_boundary": "Fixed-schema adapter; records its own input reads, does not discover arbitrary hidden dependencies."}
    write_json(output / "workflow_manifest.json", manifest)
    workload = compile_workload(manifest, output)
    write_json(output / "compatible_workload.json", workload)
    summary = {"artifacts": len(builder.artifacts), "release_effects": len(releases), "parsed_observations": count_parsed,
               "accepted_observations": count_accepted, "support_size_range": workload["support_size_range"],
               "lineage_depth_range": workload["lineage_depth_range"], "validation": validate_manifests(manifest, output)}
    write_json(output / "workflow_summary.json", summary)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("download", "run", "validate"))
    parser.add_argument("--data", type=Path, default=ROOT / "data/ghcn")
    parser.add_argument("--output", type=Path, default=ROOT / "results/ghcn_workflow_v2")
    args = parser.parse_args()
    if args.command == "download":
        result = download_sources(args.data)
    elif args.command == "run":
        result = run_workflow(args.data, args.output)
    else:
        result = validate_manifests(read_json(args.output / "workflow_manifest.json"), args.output)
    print(json.dumps(result, sort_keys=True))
