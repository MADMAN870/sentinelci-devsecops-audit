*********** You can see all this if u run the script with --help ***********

!! IMPORTANT: every screenshots must have a description "txt" file with the same name as the image (ex: screenshot.png screenshots.txt) !! 

1) create a virtual env (python -m venv venv)
2) pip install reportlab


PATHS: 

  Tools output: 

    -- test data: ./test_data/pentest/output/
    -- real data : PROJECT_ROOT/reports/pentest/outputs

  Screenshots: PROJECT_ROOT/reports/pentest/screenshots


---------------------------------------------------------------------

normalizer.py -- collapse the raw JSON output of every scanner into ONE
normalized JSON document with a fixed set of keys.

    raw tool outputs (reports/**/*.json)  --normalizer.py-->  report_data.json
                                          (keys defined by report_template.json)

Supported inputs (detected from the JSON structure first, file name second):
    OWASP ZAP   zap-api-scan.py -J   (traditional JSON report)
    Gitleaks    --report-format json
    Semgrep     --json
    Syft        syft-json, CycloneDX-json or SPDX-json
    Trivy       --format json
    Grype       -o json
    Cosign      `cosign verify` JSON output (or {"verified": bool, "error": "..."})

Tools that produced no JSON simply keep status "not_run" and empty fields.

Re-running is safe: values you typed into the manual sections (meta, pipeline,
scope, additional, remediation_plan owners/dates, finding status/impact/retest)
are preserved; only tool-derived data is regenerated.

Default layout (run from anywhere):
    reports/ReportingnEngine/templates/report_template.json  -> blank key schema
    reports/**/*.json (pentest/output, baseline, ...)         -> raw tool output
    reports/ReportingnEngine/output/report_data.json          -> result

Usage:
    python3 normalizer.py
    python3 normalizer.py --reports-dir ../pentest/output
    python3 normalizer.py --set meta.client_name="ACME Corp" --set scope.out_of_scope='["prod DB"]'

GitLab CI variables (CI_PIPELINE_ID, CI_COMMIT_SHA, ...) are picked up
automatically when present and the matching field is still empty.

----------------------------------------------------------------------

gen_report.py -- fill the LaTeX report template from the normalized JSON.

    output/report_data.json         (from normalizer.py)
  + templates/main.tex              (presentation template, left untouched)
  + templates/helper_temp.json      (narrative paragraphs with {{TOKENS}})
  + templates/conclusion.txt        (conclusion text with [TOKENS])
  + screenshots/*.png|jpg|pdf       (evidence images, each with a same-name .txt description)
  --> output/report.tex             (always)
  --> output/report.pdf             (ONLY when --pdf is passed)

  All paths are relative to this script (reports/ReportingnEngine/), so it can
  be run from any working directory.

Screenshots
  Every image in the screenshots folder is inserted into the appendix
  "Screenshots and Supporting Evidence" (LaTeX) / "C. Screenshots" (ReportLab).
  The description of an image is the .txt file with the SAME NAME in the SAME folder:

      screenshots/01_zap_sqli_login.png
      screenshots/01_zap_sqli_login.txt     <- caption / description of that image

  * Order: natural filename order (01_, 02_, ... 10_), so prefix the names to control it.
  * The whole text file becomes the figure caption; its first line (or first sentence)
    is also used as the short entry in the List of Figures.
  * Image without .txt -> inserted with a caption made from the file name (warning printed).
  * .txt without image -> ignored (warning printed).
  * Formats: png, jpg/jpeg, pdf for LaTeX; png, jpg/jpeg for ReportLab.
  * Folder lookup: --screenshots-dir, else ../pentest/screenshots, else ./screenshots.
  * Images are copied to <out-dir>/screenshots/ (with filesystem-safe names) so that
    output/report.tex is self-contained and compiles without any TEXINPUTS tricks.
  * No screenshots found -> the template placeholder is left as it is.

Placeholder policy
  * \\newcommand{\\Macro}{[...]} values and \\placeholder{...} blocks that have
    data are replaced; the ones without data are LEFT AS THEY ARE in the
    template so they stay visible, and are listed at the end of the run.
  * Nothing is ever written to disk as PDF unless --pdf is given.

PDF
  --pdf            compile report.tex with latexmk (or pdflatex x2)
  --pdf latex      same as above
  --pdf reportlab  render the same data directly with ReportLab (no TeX needed;
                   simpler layout -- ReportLab cannot compile .tex files)

Usage
  python3 gen_report.py
  python3 gen_report.py --pdf
  python3 gen_report.py --pdf reportlab --detail-min-severity low
  python3 gen_report.py --pdf --screenshots-dir /path/to/screenshots
