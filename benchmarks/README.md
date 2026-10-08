# Real-CVE benchmark

The benchmark runner scans both sides of a curated vulnerable/patched commit pair, scopes discovery to the CVE's affected file, exports per-run findings, and reports target-specific recall, precision, false-positive rate, and severity accuracy. It also reports whole-repository SAST baseline detections separately. These targeted scans validate the known CVE signature; they do not measure whole-repository discovery recall.

## Run

Start the configured model service and install the repository's backend dependencies first. Then run from the repository root:

~~~~text
python cycle11_ollama_swarm/benchmark_cves.py --manifest benchmarks/cve_manifest.example.json --output-dir results/cve_benchmark
~~~~

Set OLLAMA_URL, GROQ_API_KEY, or other model-provider configuration as needed. The runner uses the same model and scanner options as run_real_world.py; --max-chunks can limit discovery for a quick, explicitly partial run. Benchmark checkouts are temporary and removed after each CVE case. Reports and each scan's log/evidence remain in the output directory.

If SWARM_ALLOWED_SCAN_ROOT is configured, it must point to an existing directory; temporary commit checkouts are created inside it so the scanner's path jail continues to apply.

## Manifest

See cve_manifest.schema.json for the schema and cve_manifest.example.json for a sourced case. Each entry identifies:

- An allowlisted HTTPS repository URL.
- Full immutable Git commit SHAs for the vulnerable and patched states.
- The affected relative file and at least one matching CWE or finding keyword.
- An optional expected severity and line window.

The matcher requires the affected file plus a CWE or keyword match. Discovery defaults to all chunks from that affected file. A case can provide `discovery_lines` to focus on the known changed lines and ten lines of context around each; SAST still runs over the repository. The primary Swarm score counts a SAST alert only when triage calls it a true positive; confirmed discovery findings also count. Raw SAST detections are listed as a separate baseline. A post-patch match is counted as a target-specific false positive. This is not a general-purpose precision estimate for unrelated findings.

CVE identifiers, affected file signatures, severities, and commit pairs must be reviewed against the linked advisory and patch before publication. The example maps Django's advisory severity “moderate” to the scanner's MEDIUM tier. Only one verified case is included; it is a harness smoke dataset, not evidence for the roadmap's multi-project benchmark claims.

The report is written incrementally to cve_benchmark_report.json; incomplete scans are excluded from accuracy denominators, and their status/reason is retained per scan.
