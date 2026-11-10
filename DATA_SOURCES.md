# Frozen scientific inputs

NOAA GHCN-Daily, Version 3, DOI 10.7289/V5D21VHZ. Source URLs, retrieval dates,
terms URL and SHA256 hashes are preserved in data/ghcn/source_manifest.json.
The retained source readme and version record accompany the raw files. The
station screening record explains the excluded USW00014819 candidate; the
workflow uses USW00094728, USW00023174 and USW00094846, 1991–2025, with a
1991–2020 baseline. Derived reports are author-created, not official NOAA products.

inputs/ghcn_workflow_v2/workflow_manifest.json records artifact roles, generations,
actual read records and code/content identities. compatible_workload.json binds
the gateway registry and actual report payloads. The lifecycle driver runs a
separate scientific oracle before timing. To regenerate into a new directory:
python code/ghcn_workflow.py run --data data/ghcn --output NEW_ETL
Then pass NEW_ETL as --workflow to the lifecycle driver. Do not overwrite the
frozen outputs or mix regenerated manifests with original measurements.
