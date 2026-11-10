"""Independent scientific result oracle: reads original .dly, never ETL code.

The byte parser uses fixed-width struct unpacking and aggregates observations
directly into day maps. It does not consume the adapter's parsed or QC files.
Exact rational arithmetic avoids tolerance-based acceptance of wrong results.
"""
from __future__ import annotations
import argparse
import calendar
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct

STATIONS = ("USW00094728", "USW00023174", "USW00094846")
RECORD = struct.Struct("11s4s2s4s" + "5s1s1s1s" * 31)


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded_fraction(number):
    return {"numerator": number.numerator, "denominator": number.denominator}


def decoded_fraction(value):
    return Fraction(value["numerator"], value["denominator"])


def original_observations(path, station):
    observations = {}
    parsed = accepted = 0
    for line in Path(path).read_bytes().splitlines():
        if len(line) != RECORD.size:
            raise AssertionError("oracle: malformed raw row")
        row = RECORD.unpack(line)
        if row[0].decode() != station:
            raise AssertionError("oracle: wrong station id")
        year, month, element = int(row[1]), int(row[2]), row[3].decode()
        if not 1991 <= year <= 2025 or element not in ("TMIN", "TMAX", "PRCP"):
            continue
        for day in range(1, calendar.monthrange(year, month)[1] + 1):
            field = 4 + 4 * (day - 1)
            value = int(row[field])
            qflag = row[field + 2]
            key = (year, month, day, element)
            if key in observations:
                raise AssertionError("oracle: duplicate observation")
            observations[key] = value if value != -9999 and qflag == b" " and (element != "PRCP" or value >= 0) else None
            parsed += 1
    days = {}
    for (year, month, day, element), value in observations.items():
        if value is not None:
            days.setdefault((year, month, day), {})[element] = value
    for values in days.values():
        if "TMIN" in values and "TMAX" in values and values["TMIN"] > values["TMAX"]:
            del values["TMIN"], values["TMAX"]
        accepted += len(values)
    return days, parsed, accepted


def direct_expected_reports(data):
    station_reports, monthly_results, baseline_results = {}, {}, {}
    parsed = accepted = 0
    for station in STATIONS:
        days, count, valid_count = original_observations(Path(data) / "raw" / (station + ".dly"), station)
        parsed += count
        accepted += valid_count
        monthly = {}
        for year in range(1991, 2026):
            months = []
            for month in range(1, 13):
                total = Fraction()
                count = rain_count = rain_sum = 0
                for day in range(1, calendar.monthrange(year, month)[1] + 1):
                    values = days.get((year, month, day), {})
                    if "TMIN" in values and "TMAX" in values:
                        total += Fraction(values["TMIN"] + values["TMAX"], 20)
                        count += 1
                    if "PRCP" in values:
                        rain_sum += values["PRCP"]
                        rain_count += 1
                required = (9 * calendar.monthrange(year, month)[1] + 9) // 10
                months.append({"month": month, "paired_temperature_days": count, "precipitation_days": rain_count,
                               "required_days": required, "temperature_eligible": count >= required,
                               "temperature_mean_c": encoded_fraction(total / count) if count else None,
                               "precipitation_total_mm": encoded_fraction(Fraction(rain_sum, 10)),
                               "precipitation_eligible": rain_count >= required})
            monthly[year] = {"year": year, "months": months}
            monthly_results[f"monthly:{station}:{year}"] = monthly[year]
        normals = []
        for month_index in range(12):
            values = [decoded_fraction(monthly[year]["months"][month_index]["temperature_mean_c"])
                      for year in range(1991, 2021) if monthly[year]["months"][month_index]["temperature_eligible"]]
            normal = sum(values, Fraction()) / len(values) if values else None
            normals.append({"month": month_index + 1, "eligible_years": len(values),
                            "baseline_eligible": len(values) >= 25,
                            "temperature_mean_c": encoded_fraction(normal) if normal is not None else None})
        baseline_results[f"baseline:{station}"] = {"first_year": 1991, "last_year": 2020, "months": normals}
        for year in range(2021, 2026):
            results = []
            deltas = []
            for index in range(12):
                current, normal = monthly[year]["months"][index], normals[index]
                eligible = current["temperature_eligible"] and normal["baseline_eligible"]
                delta = decoded_fraction(current["temperature_mean_c"]) - decoded_fraction(normal["temperature_mean_c"]) if eligible else None
                if delta is not None:
                    deltas.append(delta)
                results.append({"month": index + 1, "eligible": eligible,
                                "temperature_anomaly_c": encoded_fraction(delta) if delta is not None else None,
                                "temperature_mean_c": current["temperature_mean_c"],
                                "paired_temperature_days": current["paired_temperature_days"],
                                "precipitation_total_mm": current["precipitation_total_mm"],
                                "precipitation_eligible": current["precipitation_eligible"]})
            station_reports[f"report:{station}:{year}"] = {
                "station": station, "year": year, "baseline": [1991, 2020], "months": results,
                "eligible_months": len(deltas),
                "annual_mean_anomaly_c": encoded_fraction(sum(deltas, Fraction()) / 12) if len(deltas) == 12 else None,
                "interpretation": "Descriptive station summary; not homogenized climate attribution."}
    reports = dict(station_reports)
    for year in range(2021, 2026):
        individual = [station_reports[f"report:{station}:{year}"] for station in STATIONS]
        reports[f"cross_report:{year}"] = {"year": year, "station_reports": individual,
                                         "eligible_station_count": sum(item["annual_mean_anomaly_c"] is not None for item in individual),
                                         "interpretation": "Selected station reports; no spatial interpolation or area-weighted climate inference."}
    return {"reports": reports, "monthlies": monthly_results, "baselines": baseline_results,
            "parsed_observations": parsed, "accepted_observations": accepted}


def verify_release_payloads(manifest, workload, expected_reports, workflow):
    """Independently check one-to-one report identity and its authorized root."""
    expected_ids = set(expected_reports)
    declared = manifest["release_artifacts"]
    effects = workload["effects"]
    actual_effect_ids = [effect["effect_id"] for effect in effects]
    if (set(declared) != expected_ids or len(declared) != len(expected_ids) or
            set(actual_effect_ids) != {"publish:" + aid for aid in expected_ids} or
            len(actual_effect_ids) != len(expected_ids)):
        raise AssertionError("oracle: missing, duplicate or extra release identities")
    root = Path(workflow).resolve()
    for effect in effects:
        payload = effect["payload"]
        aid = payload["artifact_id"]
        if aid not in expected_ids or effect["effect_id"] != "publish:" + aid:
            raise AssertionError("oracle: effect identity and payload artifact disagree")
        artifact = manifest["artifacts"][aid]
        if artifact["artifact_id"] != aid or payload["result"] != expected_reports[aid]:
            raise AssertionError("oracle: wrong gateway payload")
        if (payload["generation"] != artifact["generation"] or effect["generation"] != artifact["generation"] or
                effect["artifact_path"] != artifact["path"] or payload["content_sha256"] != artifact["sha256"]):
            raise AssertionError("oracle: unbound gateway payload")
        if workload["registry"]["effect_artifacts"].get(effect["effect_id"]) != [aid + "@" + artifact["generation"]]:
            raise AssertionError("oracle: wrong authorized report root")
        source = (root / artifact["path"]).resolve()
        if not source.is_relative_to(root):
            raise AssertionError("oracle: report path escapes workflow")
        if digest(source.read_bytes()) != artifact["sha256"]:
            raise AssertionError("oracle: report content hash mismatch")


def verify(data, workflow):
    data, workflow = Path(data), Path(workflow)
    sources = load(data / "source_manifest.json")
    for item in sources["files"]:
        if digest((data / item["path"]).read_bytes()) != item["sha256"]:
            raise AssertionError("oracle: raw source hash mismatch")
    expected = direct_expected_reports(data)
    manifest = load(workflow / "workflow_manifest.json")
    workload = load(workflow / "compatible_workload.json")
    checked = 0
    for category in ("reports", "monthlies", "baselines"):
        for aid, correct in expected[category].items():
            artifact = manifest["artifacts"][aid]
            actual = load(workflow / artifact["path"])
            if actual != correct:
                raise AssertionError("oracle: wrong independently recomputed artifact " + aid)
            checked += 1
    if manifest["parsed_observations"] != expected["parsed_observations"] or manifest["accepted_observations"] != expected["accepted_observations"]:
        raise AssertionError("oracle: input accounting mismatch")
    verify_release_payloads(manifest, workload, expected["reports"], workflow)
    return {"status": "passed", "oracle_implementation": "independent struct parser and direct daily aggregation",
            "oracle_code_sha256": digest(Path(__file__).read_bytes()), "scientific_artifacts_recomputed": checked,
            "release_payloads_recomputed": len(expected["reports"]), "release_identity_bindings_verified": len(expected["reports"]),
            "parsed_observations": expected["parsed_observations"],
            "accepted_observations": expected["accepted_observations"], "raw_sources_hash_verified": len(sources["files"])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--data", type=Path, default=root / "data/ghcn")
    parser.add_argument("--workflow", type=Path, default=root / "results/ghcn_workflow_v2")
    args = parser.parse_args()
    result = verify(args.data, args.workflow)
    (args.workflow / "oracle_validation.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
