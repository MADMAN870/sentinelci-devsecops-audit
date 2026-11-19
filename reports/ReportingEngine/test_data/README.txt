SYNTHETIC test data - NOT real scan results.

pentest/output/zap-report.json   ZAP-style (zap-api-scan.py -J) report, 7 alerts
baseline/*.json                  Gitleaks, Semgrep, Syft, Trivy, Grype, Cosign samples
                                 (the leaked "secret" is a made-up string)

Run (from reports/ReportingnEngine/):

  python3 normalizer.py --reports-dir test_data -o output/test_all.json
  python3 gen_report.py --data output/test_all.json --out-dir output/test_all --pdf

The default scan of reports/ ignores this folder, so test data never mixes with real results.
