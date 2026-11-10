"""Mutation and boundary tests for the actual NOAA workflow adapter."""
import copy
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ghcn_workflow import Builder, canonical, generation_record, monthly_statistics, parse_year, quality_filter, sha, validate_manifests
from ghcn_oracle import original_observations

TEST_ROOT = Path(__file__).resolve().parents[2] / "build/ghcn_test_tmp"
TEST_ROOT.mkdir(parents=True, exist_ok=True)


def raw_row(element, values, year=2024, month=2, station="USW00094728"):
    data = f"{station}{year:04d}{month:02d}{element}"
    for day in range(31):
        value, qflag = values.get(day + 1, (-9999, " "))
        data += f"{value:5d} {qflag}0"
    return (data + "\n").encode()


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root = Path(self.temp.name)
        self.builder = Builder(self.root)
        self.builder.add("raw", "source", {}, {}, lambda _: b"raw")
        self.builder.add("format", "policy", {}, {}, lambda _: {"x": 1})
        self.builder.add("parsed", "parse_year", {"year": 2024},
                         {"raw_station": "raw", "format_policy": "format"}, lambda _: b"parsed")
        self.manifest = {"artifacts": self.builder.artifacts, "execution_reads": self.builder.execution_reads}

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_transitive_binding(self):
        result = validate_manifests(self.manifest, self.root)
        self.assertEqual(result, {"artifacts_verified": 3, "read_events_verified": 2})

    def test_omitted_input_rejected_even_if_read_log_also_edited(self):
        bad = copy.deepcopy(self.manifest)
        bad["artifacts"]["parsed"]["inputs"] = [item for item in bad["artifacts"]["parsed"]["inputs"] if item["role"] != "format_policy"]
        bad["execution_reads"] = [item for item in bad["execution_reads"] if item["role"] != "format_policy"]
        bad["artifacts"]["parsed"]["generation"] = sha(canonical(generation_record(bad["artifacts"]["parsed"])))
        with self.assertRaisesRegex(ValueError, "required input"):
            validate_manifests(bad, self.root)

    def test_parent_generation_mismatch_rejected(self):
        bad = copy.deepcopy(self.manifest)
        bad["artifacts"]["parsed"]["inputs"][0]["generation"] = "0" * 64
        bad["execution_reads"][0]["generation"] = "0" * 64
        bad["artifacts"]["parsed"]["generation"] = sha(canonical(generation_record(bad["artifacts"]["parsed"])))
        with self.assertRaisesRegex(ValueError, "parent generation"):
            validate_manifests(bad, self.root)

    def test_output_hash_mismatch_rejected(self):
        target = self.root / self.manifest["artifacts"]["raw"]["path"]
        target.write_bytes(b"modified bytes")
        with self.assertRaisesRegex(ValueError, "content hash"):
            validate_manifests(self.manifest, self.root)

    def test_input_hash_mismatch_rejected(self):
        bad = copy.deepcopy(self.manifest)
        bad["artifacts"]["parsed"]["inputs"][0]["sha256"] = "f" * 64
        bad["execution_reads"][0]["sha256"] = "f" * 64
        bad["artifacts"]["parsed"]["generation"] = sha(canonical(generation_record(bad["artifacts"]["parsed"])))
        with self.assertRaisesRegex(ValueError, "parent generation or content hash"):
            validate_manifests(bad, self.root)

    def test_changed_parameter_without_new_generation_rejected(self):
        bad = copy.deepcopy(self.manifest)
        bad["artifacts"]["parsed"]["parameters"]["year"] = 2023
        with self.assertRaisesRegex(ValueError, "generation mismatch"):
            validate_manifests(bad, self.root)

    def test_changed_implementation_identity_rejected(self):
        bad = copy.deepcopy(self.manifest)
        bad["adapter_code_sha256"] = bad["artifacts"]["raw"]["implementation_sha256"]
        bad["artifacts"]["parsed"]["implementation_sha256"] = "f" * 64
        bad["artifacts"]["parsed"]["generation"] = sha(canonical(generation_record(bad["artifacts"]["parsed"])))
        with self.assertRaisesRegex(ValueError, "implementation identity"):
            validate_manifests(bad, self.root)

    def test_mandatory_thirty_year_baseline_inputs(self):
        with self.assertRaisesRegex(ValueError, "step input schema"):
            self.builder.add("incomplete_normal", "baseline", {}, {"baseline_policy": "format"}, lambda _: {})

    def test_artifact_path_escape_rejected(self):
        bad = copy.deepcopy(self.manifest)
        bad["artifacts"]["raw"]["path"] = "../outside.dat"
        with self.assertRaisesRegex(ValueError, "escapes"):
            validate_manifests(bad, self.root)


class ClimateBoundaryTests(unittest.TestCase):
    def test_leap_day_and_independent_parser_agree(self):
        raw = raw_row("TMIN", {29: (100, " ")}) + raw_row("TMAX", {29: (200, " ")})
        parsed = list(csv.DictReader(io.StringIO(parse_year(raw, 2024, "USW00094728").decode())))
        self.assertEqual(len(parsed), 58)
        self.assertIn("2024-02-29", [row["date"] for row in parsed])
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as folder:
            source = Path(folder) / "station.dly"
            source.write_bytes(raw)
            days, count, accepted = original_observations(source, "USW00094728")
            self.assertEqual((count, accepted), (58, 2))
            self.assertEqual(days[(2024, 2, 29)], {"TMIN": 100, "TMAX": 200})

    def test_qflag_missing_negative_rain_and_inverted_temperatures(self):
        raw = raw_row("TMIN", {1: (100, "X"), 2: (300, " "), 3: (0, " ")})
        raw += raw_row("TMAX", {1: (200, " "), 2: (200, " "), 3: (100, " ")})
        raw += raw_row("PRCP", {1: (-1, " "), 2: (0, " "), 3: (10, " ")})
        filtered = quality_filter(parse_year(raw, 2024, "USW00094728"), {"missing_value": -9999, "accepted_qflags": [""]})
        valid = [row for row in csv.DictReader(io.StringIO(filtered.decode())) if row["accepted"] == "1"]
        self.assertEqual(len(valid), 5)
        self.assertFalse(any(row["date"] == "2024-02-02" and row["element"] in ("TMIN", "TMAX") for row in valid))
        summary = monthly_statistics(filtered, 2024, {"coverage_numerator": 9, "coverage_denominator": 10})["months"][1]
        self.assertEqual(summary["paired_temperature_days"], 1)
        self.assertEqual(summary["temperature_mean_c"], {"numerator": 5, "denominator": 1})
        self.assertEqual(summary["required_days"], 27)
        self.assertFalse(summary["temperature_eligible"])

    def test_duplicate_and_wrong_station_rejected(self):
        raw = raw_row("PRCP", {})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_year(raw + raw, 2024, "USW00094728")
        with self.assertRaisesRegex(ValueError, "station identity"):
            parse_year(raw, 2024, "USW00023174")


if __name__ == "__main__":
    unittest.main()
