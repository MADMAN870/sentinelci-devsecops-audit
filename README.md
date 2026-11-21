# SentinelCI

**DevSecOps penetration testing and security audit of a CI/CD software supply chain.**

SentinelCI deploys a complete DevOps lab (GitLab CE, a runner and a container registry, all in Docker), pushes a deliberately vulnerable API ([VAmPI](https://github.com/erev0s/VAmPI)) through its CI/CD pipeline, and audits the whole chain: secrets, source code, dependencies, container images, SBOMs, image signatures and the running API. The output of every scanner is normalised into one data file and rendered as a LaTeX/PDF penetration-testing report. A web dashboard and a pentest runner drive and display the scans.

Built for the 5CIR *Ethical Hacking & Pentesting* course, Subject 9: *DevSecOps Penetration Testing — advanced audit of a CI/CD infrastructure*.

## Contents

- [What it covers](#what-it-covers)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Getting started](#getting-started)
- [Running the scanners](#running-the-scanners)
- [Reporting engine](#reporting-engine)
- [Security and responsible use](#security-and-responsible-use)
- [Credits](#credits)

---

## What it covers

| Area | Tool | What it finds |
|---|---|---|
| Secrets | **Gitleaks** | Hard-coded credentials in the repository and its Git history |
| SAST | **Semgrep** | Insecure code patterns in the application source |
| SBOM | **Syft** | Package inventory of the built image (CycloneDX, SPDX or Syft JSON) |
| Dependencies and images | **Trivy** | Known CVEs, misconfigurations and secrets in dependencies, the Dockerfile and the image |
| SBOM analysis | **Grype** | Known vulnerabilities matched against the SBOM |
| Image signing | **Cosign** | Image signature and verification result |
| Dynamic API testing | **OWASP ZAP** | Runtime weaknesses found by an OpenAPI-driven scan of the running API |
| Manual track | analyst | Review of accounts, permissions and CI/CD tokens; controlled pipeline-abuse scenarios, with screenshots and traces as evidence |

The target, VAmPI, is a Flask REST API with deliberate flaws such as SQL injection, broken object-level authorization, mass assignment, excessive data exposure, user enumeration, ReDoS, missing rate limiting and a weak JWT signing key.

## How it works

The audit runs on two tracks that meet in one report: an **automated track** (what the tools detect) and a **manual track** (what an attacker can actually do). The same scanners are re-run after hardening (secrets removed and rotated, dependencies updated, non-root image, least-privilege tokens, security gates in the pipeline) so the security level can be compared before and after.

```
target-app (VAmPI) ──► GitLab CI/CD ──► Gitleaks · Semgrep · Syft · Trivy · Grype · Cosign ──┐
                         └─► pentest-runner ──► OWASP ZAP (API scan, Docker) ────────────────┤
                                                                                              ▼
                                       raw tool JSON  (reports/baseline, reports/pentest/output)
                                                                                              │
                          normalizer.py ──► output/report_data.json ──► gen_report.py ──► report.tex ──► report.pdf
                                              (fixed set of keys)        (fills main.tex)
```

## Repository layout

```
sentinelci-devsecops-audit/
├── docs/
│   ├── arch/                       Architecture documentation
│   └── report/                     Report deliverables
├── infra/                          Lab / infrastructure definitions
├── pentest-runner/
│   ├── config/                     Runner configuration
│   ├── scripts/                    Scan scripts (for example the ZAP API scan in Docker)
│   └── watcher/                    Watcher process of the pentest runner
├── reports/
│   ├── baseline/                   Scan output before hardening (kept for comparison)
│   ├── pentest/
│   │   ├── output/                 Pentest tool output (ZAP JSON and HTML, ...)
│   │   └── screenshots/            Screenshots used as evidence
│   └── ReportingnEngine/           Normalizer and LaTeX report generator
│       ├── normalizer.py           Raw tool JSON  ->  report_data.json
│       ├── gen_report.py           report_data.json + templates  ->  report.tex (+ PDF on request)
│       ├── selftest.py             Runs every scenario against test_data/
│       ├── templates/              main.tex, helper_temp.json, conclusion.txt, report_template.json
│       └── test_data/              Synthetic scanner output for testing
├── sentinelci-devsecops-audit-dashboard/
│   ├── pages/
│   │   ├── api/{auth,docker,reports}/   API routes: authentication, Docker control, report access
│   │   └── tools/                       Tool pages
│   ├── lib/  data/  styles/
└── target-app/                     VAmPI sources (api_views, models, database, openapi_specs)
```

## Getting started

### Prerequisites

- Docker and Docker Compose v2
- Git
- About 8 GB of free RAM (GitLab is heavy)
- Python 3.9 or newer for the reporting engine

### 1. Clone

```bash
git clone https://github.com/MADMAN870/sentinelci-devsecops-audit.git
cd sentinelci-devsecops-audit
```

### 2. Allow the local HTTP registry

```bash
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{ "insecure-registries": ["localhost:5050"] }
EOF
sudo systemctl restart docker
```

### 3. Start GitLab and the runner

Run from the repository root:

```bash
docker compose up -d gitlab gitlab-runner
docker compose logs -f gitlab | grep -i "GitLab is up"     # about 5-10 minutes
```

### 4. Sign in to GitLab

```bash
docker compose exec gitlab cat /etc/gitlab/initial_root_password
```

Open <http://localhost:8080> and sign in as `root`.

### 5. Create a project and push the repository

```bash
git remote add localgitlab http://localhost:8080/<namespace>/<project>.git
git push localgitlab main
```

### 6. Register the runner

Get a token in **Settings → CI/CD → Runners → New project runner**, then:

```bash
docker compose exec gitlab-runner gitlab-runner register \
  --non-interactive \
  --url "http://gitlab" \
  --token "<RUNNER_TOKEN>" \
  --executor "docker" \
  --docker-image "alpine:latest" \
  --docker-volumes "/var/run/docker.sock:/var/run/docker.sock" \
  --docker-network-mode "host" \
  --tag-list "<RUNNER_TAGS>"
```

`<RUNNER_TAGS>` must match the tags requested by the jobs in `.gitlab-ci.yml`. The runner uses `--docker-network-mode host` so that job containers can reach `localhost:8080` (GitLab) and `localhost:5050` (registry).

### 7. Log in to the registry

```bash
docker login localhost:5050 -u root       # root password from step 4
```

### 8. Cosign keys (optional)

Add these as masked variables in **GitLab project → CI/CD → Variables**: `COSIGN_PRIVATE_KEY`, `COSIGN_PUBLIC_KEY`, `COSIGN_PASSWORD`. The pipeline signs the image only when `COSIGN_PRIVATE_KEY` is set.

### 9. Trigger the pipeline

```bash
git commit --allow-empty -m "trigger pipeline"
git push localgitlab main
```

Follow it in **GitLab → Build → Pipelines**.

### Running the target locally

VAmPI listens on port 5000. To try the upstream image without the pipeline:

```bash
docker run -p 5000:5000 erev0s/vampi:latest
curl http://localhost:5000/createdb        # creates and populates the database
```

## Running the scanners

### Manual runs

These produce JSON that the reporting engine understands. Replace `<image>` with the image under test.

```bash
# Secrets
gitleaks detect --source . --report-format json --report-path reports/baseline/gitleaks.json

# SAST
semgrep scan --config auto --json -o reports/baseline/semgrep.json target-app/

# Dependencies, Dockerfile and image
trivy fs    --format json -o reports/baseline/trivy-fs.json    target-app/
trivy image --format json -o reports/baseline/trivy-image.json <image>

# SBOM, then vulnerability analysis of the SBOM
syft docker-archive:image.tar -o cyclonedx-json=reports/baseline/sbom.cdx.json
grype sbom:reports/baseline/sbom.cdx.json -o json > reports/baseline/grype.json

# Signature verification
cosign verify --key cosign.pub <image> > reports/baseline/cosign-verify.json
```

`cosign verify` prints no JSON when it fails. To have the failure reported, write `{"verified": false, "error": "<message>"}` to the output file instead.

### OWASP ZAP API scan

The pentest runner scans the API from its OpenAPI definition with the official ZAP image:

```bash
docker run --rm \
	"${NETWORK_ARGS[@]}" \
	-v "$(cd "$RESULTS_DIR" && pwd)":/zap/wrk/:rw \
	-v "$SPEC_DIR":/zap/spec/:ro \
	-t "$ZAP_IMAGE" zap-api-scan.py \
	-t "/zap/spec/$SPEC_FILENAME" -f openapi \
	-J "$REPORT_JSON" -r "$REPORT_HTML" \
	-m "$ZAP_TIMEOUT_MIN" -I
```

| Variable | Meaning |
|---|---|
| `NETWORK_ARGS` | Docker network options so the ZAP container can reach the API |
| `RESULTS_DIR` | Host directory that receives the reports, mounted at `/zap/wrk` (use `reports/pentest/output`) |
| `SPEC_DIR`, `SPEC_FILENAME` | Host directory and file name of the OpenAPI definition, mounted read-only at `/zap/spec` (VAmPI's is in `target-app/openapi_specs`) |
| `ZAP_IMAGE` | ZAP Docker image |
| `REPORT_JSON`, `REPORT_HTML` | Report file names (`-J`, `-r`) |
| `ZAP_TIMEOUT_MIN` | Scan time limit in minutes (`-m`) |

`-f openapi` selects the input format and `-I` stops ZAP from failing the run on warnings.

## Reporting engine

`reports/ReportingnEngine/` turns raw scanner output into the report. All paths are relative to the scripts, so they can be run from any directory.

```bash
cd reports/ReportingnEngine

python3 normalizer.py                      # reports/**/*.json  ->  output/report_data.json
python3 gen_report.py                      # report_data.json + templates  ->  output/report.tex
python3 gen_report.py --pdf                # ... and compile it to output/report.pdf
```

A PDF is only produced when `--pdf` is given.

### Normalizer

`normalizer.py` scans `reports/` recursively (skipping `ReportingnEngine/` itself), recognises each tool from the structure of its JSON (file name is the fallback), and fills the fixed key set defined in `templates/report_template.json`:

- **Supported input:** ZAP (`-J`), Gitleaks, Semgrep, Syft (Syft JSON, CycloneDX, SPDX), Trivy, Grype, Cosign. A tool with no output stays `not_run` with empty fields.
- **Severity:** normalised to Critical / High / Medium / Low / Informational. ZAP risk codes map directly, Semgrep `ERROR`/`WARNING`/`INFO` map to High/Medium/Low, Gitleaks findings are High, and a failed Cosign verification is Medium.
- **De-duplication:** the same CVE and package reported by Trivy and Grype becomes a single finding.
- **Secrets are never copied.** Gitleaks and Trivy secret values are redacted before anything is written.
- **Safe to re-run:** values you entered by hand (metadata, scope, pipeline details, finding `status`, `impact`, retest fields) are preserved; only tool-derived data is regenerated.
- **GitLab CI variables** (`CI_PIPELINE_ID`, `CI_PIPELINE_URL`, `CI_COMMIT_SHA`, `CI_COMMIT_REF_NAME`, `CI_PROJECT_URL`, `CI_PROJECT_PATH`, `CI_RUNNER_DESCRIPTION`, `CI_PROJECT_TITLE`) fill the matching empty fields automatically.

Name Gitleaks and Cosign output files after the tool (an empty Gitleaks report is just `[]`, which has no structure to recognise).

Set the manual fields with `--set` or by editing `output/report_data.json`:

```bash
python3 normalizer.py \
  --set meta.client_name="ACME Corp" \
  --set meta.prepared_by="Security Team" \
  --set meta.target_environment="Docker lab" \
  --set meta.testing_type="Grey box" \
  --set 'scope.out_of_scope=["Production systems","Third-party services"]'
```

### Report generator

`gen_report.py` fills `templates/main.tex` (left untouched), `templates/helper_temp.json` (narrative paragraphs) and `templates/conclusion.txt` from the data file and writes `output/report.tex`. Placeholders that have data are replaced; those without data stay in the document as visible placeholders and are listed when the script finishes.

| Option | Purpose |
|---|---|
| `--pdf` / `--pdf latex` | Compile `report.tex` with `latexmk` (or `pdflatex`, two passes) |
| `--pdf reportlab` | Render the same data directly with ReportLab; no TeX needed, simpler layout |
| `--detail-min-severity LEVEL` | Findings at or above this level get a detailed section (default `medium`); all findings stay in the summary table |
| `--out-dir DIR`, `--name NAME` | Output location and base name |
| `--assets-dir DIR` | Extra folder for `\includegraphics` files (default `reports/pentest`, so `screenshots/x.png` resolves) |
| `--keep-aux` | Keep LaTeX auxiliary files |

Requirements for PDF output:

- **LaTeX:** a TeX Live with the packages loaded at the top of `templates/main.tex`. If `datetime2` or `tracklang` is missing, install it or delete the unused `\usepackage{datetime2}` line.
- **ReportLab:** `pip install reportlab`.

### Before and after hardening

Run the pipeline once per phase and keep the results apart:

```bash
python3 normalizer.py --reports-dir ../baseline -o output/baseline.json
python3 gen_report.py --data output/baseline.json --out-dir output/baseline --pdf
```

Repeat with the hardened scan output and compare the two reports.

### Testing

`test_data/` holds synthetic output for all seven tools; the default scan ignores it, so it never mixes with real results.

```bash
python3 selftest.py                        # runs every scenario in a temporary folder
python3 normalizer.py --reports-dir test_data/pentest/output -o output/test_zap.json   # ZAP only
python3 normalizer.py --reports-dir test_data -o output/test_all.json                  # all tools
```

## Security and responsible use

- The lab is **deliberately vulnerable**. Run it on an isolated network and never expose GitLab, the registry or VAmPI to the internet.
- Only scan systems you own or are explicitly authorised to test.
- All secrets planted in the lab are synthetic placeholders.
- Scan output and evidence can contain sensitive details. Treat `reports/` as confidential; the report template is classified `CONFIDENTIAL` by default.

## Credits

[VAmPI](https://github.com/erev0s/VAmPI) by erev0s (MIT licence) is the vulnerable API used as the target. Gitleaks, Semgrep, Syft, Trivy, Grype, Cosign and OWASP ZAP are the work of their respective projects.
