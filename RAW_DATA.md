# Raw measurements

This repository contains the code, tests, frozen measured runtime, workflow inputs,
NOAA GHCN-Daily source files, figure and table scripts, and the analysed result
summaries from which every table and figure in the paper is regenerated
(`ready_tables.py`, `figure_sources/plot_ready.py`).

The per-run raw measurements (about 5.9 GB, 48,963 files, including server
snapshots larger than GitHub's 100 MB file limit) are distributed as the release
asset `ESM_2_Reproducibility_Artifact.zip`. `ARTIFACT_MANIFEST.json` lists every
file of that archive with its size and SHA-256 hash, so files in this repository
and in the archive can be checked against the same manifest.

## Download and verify

- [Complete raw-measurement archive](https://github.com/ermalimust/exact-incremental-release-validation/releases/download/v1.0.0/ESM_2_Reproducibility_Artifact.zip)
- [Release page](https://github.com/ermalimust/exact-incremental-release-validation/releases/tag/v1.0.0)
- Compressed size: 473,934,988 bytes.
- SHA-256: `841b842690f1909f5c1c0fc083995f037b16e54bd7be8267acfeebc6bd0d2f48`.

ARTIFACT_MANIFEST.json describes the complete frozen release archive. The
repository uses the same code, inputs and numerical summaries. README.md and
RUNTIME_VERSIONS.txt have publication-only updates for the current journal
and repository location, so their repository hashes differ from the frozen
archive. REPOSITORY_MANIFEST.json records the hashes of the current repository
files and identifies these documentation differences.
