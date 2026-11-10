# Reproducibility material

This artifact contains the measured runtime and its maintained successor for *Exact Incremental Release
Validation for Workflows with Revocable Provenance*, by Lin Huang and Li Feng.
Prepared for submission to Software: Practice and Experience (Wiley).
Corresponding author: Li Feng, lfeng@must.edu.mo.
Affiliations: School of Computer Science and Engineering, Macau University of
Science and Technology, Macau, China; Zhuhai MUST Science and Technology Research
Institute, Zhuhai, China. The manuscript has not yet been published; no publication DOI is claimed.
Repository: https://github.com/ermalimust/exact-incremental-release-validation.

The frozen measured runtime is in `measured_runtime/code`; its exact hashes are
in `measured_runtime/MEASURED_CODE_MANIFEST.json`. Retained results refer to
that runtime. The maintained `code` directory adds nonempty-effect-ID validation
and explicitly rejects legacy databases containing an empty or NULL effect ID.
All retained performance results use the frozen measured runtime; the
maintained input-domain patch has not been benchmarked.
See RUNTIME_VERSIONS.txt for the distinction and database compatibility policy.

Python 3.12 and its standard library run gateway experiments and independent
oracles. numpy and matplotlib are needed only for figures. Experiments use one
physical host. Run from this directory, with fresh outputs on nonsynchronized
local storage. Never overlap timing with other benchmarks, tests, ETL, plotting
or TeX compilation. Commands below start new experiments; reading retained JSON
and CSV files does not require rerunning them.

```text
python measured_runtime/code/lifecycle_benchmark.py --suite all --workflow inputs/ghcn_workflow_v2 --data data/ghcn --repeats 30 --out NEW_LIFECYCLE
python measured_runtime/code/retention_suite.py --seeds 5 --output NEW_RETENTION
python measured_runtime/code/continuous_analysis.py --runs NEW_RETENTION --out NEW_RETENTION_ANALYSIS
python measured_runtime/code/continuous_cleanup_suite.py --seeds 3 --output NEW_CLEANUP
python measured_runtime/code/continuous_analysis.py --runs NEW_CLEANUP --out NEW_CLEANUP_ANALYSIS
python measured_runtime/code/lifecycle_benchmark.py --suite history-gap --out NEW_HISTORY
python -m unittest discover -s code/tests -v
```

Regenerate the supplied table values from already retained summaries (after
timing stops) with `python ready_tables.py`, run from this artifact root. It
uses results/lifecycle, results/retention/analysis/continuous_analysis.json,
results/cleanup/analysis/continuous_analysis.json and the retained history
observations. It writes paper/tables/ready_*.tex and qa/final_numbers.json;
those output directories are created as needed. It performs no experiment or
new bootstrap. See figure_sources/FIGURE_REPRODUCTION.txt for the exact figure
command using the same retained result paths.

The retained lifecycle directory contains 810 synthetic and 360 workflow runs
(30 paired seeds, 2026110901-2026110930, measured on 10 November 2026),
randomized within one combined suite; use --suite all to reproduce that order.
The scientific ETL is frozen and excluded from release timings. Full wall time
includes setup; operational wall excludes setup but includes maintenance and
release operations. Nested components must not be added to enclosing windows.
Retention uses 120 s, nominal 40 updates/s and H=1024; the default lifecycle and
history-gap limit is H=4096. Cleanup has 12 runs: two backlog sizes, two modes
and three seeds. results/workflow_deadlines holds six functional boundary cases.
Performance seeds are whole-run replications. Windows process CPU observations
in this cohort are quantized to 15.625 ms; nanosecond-returning APIs do not imply
that effective resolution. All findings are local and exploratory.

This repository contains code, frozen inputs, analysed summaries and independent
checks. Complete per-run raw measurements are supplied in the accompanying
[release asset](https://github.com/ermalimust/exact-incremental-release-validation/releases/download/v1.0.0/ESM_2_Reproducibility_Artifact.zip); see [RAW_DATA.md](RAW_DATA.md). SQLite databases, process readiness files, transient logs,
internal reviews, pilot outputs and conversation traces are excluded. Numerical
audit JSON is scientific evidence, not an internal editorial review. Results
may retain original run-path metadata to preserve frozen input digests; use the
portable commands above for reproduction. The full release archive is described by ARTIFACT_MANIFEST.json.
REPOSITORY_MANIFEST.json checks the files in this compact repository, including
publication documentation updated after the frozen archive was created.
Use the retained raw dataset rather than downloading potentially changed bytes.
inputs/ghcn_workflow_v2/artifacts holds the 346 derived workflow files read by the
lifecycle preflight; each matches the SHA-256 recorded in workflow_manifest.json
and can be regenerated from data/ghcn as described in DATA_SOURCES.md.
See DATA_SOURCES.md, LICENSE_STATUS.txt, CITATION.cff and the figure instructions.
checks/cleanup_functional_witnesses.json records actual bounded-row witnesses.
checks/final_regression_summary.json is the original measured-runtime summary
(211 tests), not a reconstructed per-test transcript. The separately recorded
checks/final_patch_regression_summary.json binds the maintained code to the
final regression run. The test command above uses maintained code; to rerun
the original suite, use `python -m unittest discover -s measured_runtime/code/tests -v`.
New experiments with maintained code can use `code/` in place of
`measured_runtime/code/`, but their measurements must be kept separate from
the retained cohort. The public archive contains no internal review reports.

## Retained data and release

The [v1.0.0 release](https://github.com/ermalimust/exact-incremental-release-validation/releases/tag/v1.0.0) contains the complete retained measurements.
The compact repository is sufficient to regenerate the supplied tables and
figures from saved summaries; the release archive also provides per-run raw
evidence. See RAW_DATA.md for archive size, SHA-256 and verification details.
