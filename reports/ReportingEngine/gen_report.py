#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from normalizer import SEV_LABEL, SEV_RANK, SEVERITIES, join_list  # same directory

HERE = Path(__file__).resolve().parent

TOKEN_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
BRACKET_RE = re.compile(r"\[([A-Z][A-Z0-9_]{2,})\]")

CATEGORY_IMPACT = {
    "SECRETS": "unauthorized access to the systems, services or data protected by the exposed "
    "credential, and possible lateral movement if the credential is reused",
    "SAST": "exploitation of the flagged code path, which may affect confidentiality, integrity "
    "or availability depending on the weakness class",
    "DEPENDENCY": "exploitation of the known vulnerability in the affected third-party component, "
    "with consequences that depend on the specific advisory and on how the component is used",
    "CONTAINER": "exploitation of the known vulnerability or weakness in the affected container image "
    "component, with consequences that depend on the specific advisory and on exposure",
    "API": "abuse of the affected API endpoint(s), which may expose data, bypass access controls "
    "or degrade the service depending on the weakness",
    "SUPPLY CHAIN": "deployment of container images whose provenance or integrity cannot be verified",
}
DEFAULT_IMPACT = (
    "loss of confidentiality, integrity or availability of the affected component"
)


_UNI = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2013": "--",
    "\u2014": "---",
    "\u2026": "...",
    "\u00a0": " ",
    "\u2192": "->",
    "\u2022": "*",
    "\u2212": "-",
    "\u00ad": "",
}
_TEX = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}
_WRAP_CHARS = set("/._:=?&,;")


def sanitize(s) -> str:
    s = "" if s is None else str(s)
    for k, v in _UNI.items():
        s = s.replace(k, v)
    return "".join(ch if (ch in "\n\t" or 32 <= ord(ch) <= 0xFF) else "?" for ch in s)


def esc(s, wrap: bool = False) -> str:
    out = []
    for ch in sanitize(s).replace("\n", " ").replace("\t", " "):
        out.append(_TEX.get(ch, ch))
        if wrap and ch in _WRAP_CHARS:
            out.append(r"\allowbreak{}")
    return "".join(out)


def esc_par(s) -> str:
    lines = [l.strip() for l in sanitize(s).split("\n") if l.strip()]
    return "\n\n".join(esc(l) for l in lines)


def pdf_plain(s) -> str:
    return re.sub(r"[\\{}$&#^_%~]", "", sanitize(s)).replace("\n", " ")


def pick(*vals) -> str:
    for v in vals:
        if v not in (None, ""):
            return str(v)
    return ""


def plain_fill(text: str, values: dict, rx=TOKEN_RE):
    missing = []

    def sub(m):
        v = values.get(m.group(1))
        if v in (None, ""):
            missing.append(m.group(1))
            return m.group(0)
        return str(v)

    return rx.sub(sub, text), uniq_list(missing)


def uniq_list(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def ascii_listing(s: str, max_lines: int = 25, max_chars: int = 3000) -> str:
    s = sanitize(s).encode("ascii", "replace").decode("ascii")
    s = s.replace("\\end{lstlisting}", "\\end {lstlisting}")
    lines = s.splitlines()
    cut = len(lines) > max_lines
    s = "\n".join(lines[:max_lines])
    if cut or len(s) > max_chars:
        s = s[:max_chars] + "\n... [truncated]"
    return s


# screenshots: <name>.png + <name>.txt  ->  figure with caption
SHOT_EXTS = {".png", ".jpg", ".jpeg", ".pdf"}  # what pdflatex can include
SHOT_EXTS_REPORTLAB = {".png", ".jpg", ".jpeg"}  # what ReportLab can draw
SHOT_SUBDIR = "screenshots"  # <out-dir>/screenshots/ (staging copy)


def natural_key(s: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s)]


def read_text_any(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def pretty_title(stem: str) -> str:
    t = re.sub(r"^\d+[\s._-]*", "", stem)
    t = re.sub(r"[_\-.]+", " ", t).strip() or stem
    return t[:1].upper() + t[1:]


def caption_parts(text: str, fallback: str) -> tuple[str, str]:
    lines = [l.strip() for l in sanitize(text).splitlines() if l.strip()]
    if not lines:
        return fallback, fallback
    # join lines into one paragraph; a line without end punctuation (e.g. a title line) gets a full stop
    full = lines[0]
    for ln in lines[1:]:
        full += (" " if full[-1] in ".!?:;" else ". ") + ln
    short = (
        lines[0] if len(lines) > 1 else re.split(r"(?<=[.!?])\s", full, maxsplit=1)[0]
    )
    short = short.rstrip(".")
    if len(short) > 90:
        short = short[:88].rsplit(" ", 1)[0].rstrip(" ,;:-") + "..."
    return short, full


def find_screenshot_dir(explicit: Path | None) -> Path | None:
    if explicit:
        return explicit
    for cand in (HERE.parent / "pentest" / SHOT_SUBDIR, HERE / SHOT_SUBDIR):
        if cand.is_dir():
            return cand
    return None


def collect_screenshots(shot_dir: Path, out_dir: Path) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    if not shot_dir.is_dir():
        return [], [f"screenshots folder not found: {shot_dir}"]

    files = [f for f in shot_dir.iterdir() if f.is_file()]
    texts = {f.stem.lower(): f for f in files if f.suffix.lower() == ".txt"}
    images = sorted(
        (f for f in files if f.suffix.lower() in SHOT_EXTS),
        key=lambda f: natural_key(f.name),
    )
    for f in sorted(files, key=lambda f: natural_key(f.name)):
        if f.suffix.lower() not in SHOT_EXTS | {".txt"} and not f.name.startswith("."):
            warnings.append(f"screenshots: unsupported file ignored: {f.name}")

    try:
        from PIL import Image as _PILImage
    except ImportError:
        _PILImage = None

    stage = out_dir / SHOT_SUBDIR
    same_dir = stage.resolve() == shot_dir.resolve()
    if not same_dir:
        stage.mkdir(parents=True, exist_ok=True)
    used_stems: set[str] = set()
    shots: list[dict] = []

    for img in images:
        if _PILImage is not None and img.suffix.lower() != ".pdf":
            try:
                with _PILImage.open(img) as im:
                    im.verify()
            except Exception as exc:  # noqa: BLE001
                warnings.append(
                    f"screenshots: {img.name} is not a readable image ({exc}); skipped"
                )
                continue
        txt = texts.get(img.stem.lower())
        fallback = pretty_title(img.stem)
        if txt is not None:
            raw = read_text_any(txt)
            short, caption = caption_parts(raw, fallback)
            has_text = bool(raw.strip())
            if not has_text:
                warnings.append(
                    f"screenshots: {txt.name} is empty; using the file name as caption"
                )
        else:
            short, caption, has_text = fallback, fallback, False
            warnings.append(
                f"screenshots: no description file for {img.name} "
                f"(expected {img.stem}.txt); using the file name as caption"
            )

        slug = re.sub(r"[^A-Za-z0-9_-]+", "-", img.stem).strip("-") or "image"
        stem, n = slug, 2
        while stem.lower() in used_stems:
            stem, n = f"{slug}-{n}", n + 1
        used_stems.add(stem.lower())
        fname = stem + img.suffix.lower()
        if same_dir:
            fname = img.name
        else:
            shutil.copy2(img, stage / fname)
        shots.append(
            {
                "name": img.name,
                "source": img,
                "tex_path": f"{SHOT_SUBDIR}/{fname}",
                "label": "fig:shot-"
                + re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-"),
                "short": short,
                "caption": caption,
                "has_text": has_text,
            }
        )

    image_stems = {i.stem.lower() for i in images}
    for stem, f in sorted(texts.items()):
        if stem not in image_stems:
            warnings.append(f"screenshots: {f.name} has no matching image; ignored")
    return shots, warnings


def tex_screenshots(shots: list[dict]) -> str:
    out = [
        esc_par(
            f"This appendix contains {len(shots)} screenshot(s) collected as supporting "
            "evidence during the assessment. The caption of each figure is its description."
        )
    ]
    for sh in shots:
        out.append(
            "\\begin{figure}[H]\n"
            "    \\centering\n"
            f"    \\includegraphics[width=\\linewidth,height=0.6\\textheight,keepaspectratio]"
            f"{{{sh['tex_path']}}}\n"
            f"    \\caption[{{{esc(sh['short'])}}}]{{{esc(sh['caption'])}}}\n"
            f"    \\label{{{sh['label']}}}\n"
            "\\end{figure}"
        )
    return "\n\n".join(out)


# model: everything the renderers need, as plain (unescaped) strings
def build_model(
    data: dict,
    helper: dict,
    conclusion_txt: str,
    min_sev: str,
    screenshots: list | None = None,
) -> dict:
    meta, pipe, scope = data["meta"], data["pipeline"], data["scope"]
    summ, tools, add = data["summary"], data["tools"], data["additional"]
    counts = summ["severity_counts"]
    findings = data["findings"]

    risk = pick(meta["overall_risk"], summ["suggested_overall_risk"])
    ok_tools = [t for t in tools.values() if t["status"] == "ok"]
    missing_tools = [
        t["display_name"] for t in tools.values() if t["status"] == "not_run"
    ]
    derived_limits = (
        "findings are based on automated scanner output and were not manually validated "
        "unless their status states otherwise"
    )
    if missing_tools:
        derived_limits += (
            f"; no JSON output was available for {join_list(missing_tools)}"
        )
    tools_desc = pick(
        scope["tools_description"],
        "; ".join(f"{t['display_name']} {t['version']}".strip() for t in ok_tools)
        or "the tools listed in the assessment tools table",
    )

    macros = {
        "ReportTitle": meta["report_title"],
        "ClientName": meta["client_name"],
        "ProjectName": meta["project_name"],
        "PreparedBy": meta["prepared_by"],
        "ReportDate": pick(meta["report_date"], date.today().isoformat()),
        "AssessmentStart": pick(meta["assessment_start"], summ["scan_window_start"]),
        "AssessmentEnd": pick(meta["assessment_end"], summ["scan_window_end"]),
        "TargetEnvironment": meta["target_environment"],
        "TargetApplication": meta["target_application"],
        "ReportVersion": meta["report_version"],
        "Classification": meta["classification"],
        "OverallRisk": risk,
        "TestingType": meta["testing_type"],
        "CommitSHA": pipe["commit_sha"],
        "PipelineID": pipe["pipeline_id"],
        "PipelineURL": pipe["pipeline_url"],
        "RepositoryURL": pipe["repository_url"],
        "BranchName": pipe["branch"],
        "ReportStatus": meta["report_status"],
        "CriticalCount": counts["critical"],
        "HighCount": counts["high"],
        "MediumCount": counts["medium"],
        "LowCount": counts["low"],
        "InfoCount": counts["informational"],
        "TotalFindings": counts["total"],
    }
    macros = {k: str(v) for k, v in macros.items() if v not in (None, "")}

    values = {
        "APPLICATION_NAME": pick(meta["target_application"], "VAmPI"),
        "CLIENT_NAME": meta["client_name"],
        "ASSESSMENT_START": macros.get("AssessmentStart", ""),
        "ASSESSMENT_END": macros.get("AssessmentEnd", ""),
        "TARGET_ENVIRONMENT": meta["target_environment"],
        "ASSESSMENT_TYPE": meta["testing_type"],
        "TOTAL_FINDINGS": counts["total"],
        "CRITICAL_COUNT": counts["critical"],
        "HIGH_COUNT": counts["high"],
        "MEDIUM_COUNT": counts["medium"],
        "LOW_COUNT": counts["low"],
        "INFORMATIONAL_COUNT": counts["informational"],
        "MAIN_SECURITY_ISSUES": summ["main_security_issues"],
        "OVERALL_RISK_RATING": risk,
        "OVERALL_RISK_RATIONALE": pick(
            meta["overall_risk_rationale"], summ["suggested_risk_rationale"]
        ),
        "OUT_OF_SCOPE_COMPONENTS": "; ".join(scope["out_of_scope"]),
        "RULES_OF_ENGAGEMENT": scope["rules_of_engagement"],
        "METHODOLOGY_DESCRIPTION": scope["methodology"],
        "TOOLS_DESCRIPTION": tools_desc,
        "ASSESSMENT_LIMITATIONS": pick(scope["limitations"], derived_limits),
        "ASSUMPTIONS_AND_LIMITATIONS": pick(
            scope["assumptions_and_limitations"], derived_limits
        ),
        "PIPELINE_SECURITY_ASSESSMENT": summ["pipeline_security_assessment"],
        "ASSESSMENT_OF_PIPELINE_CONTROLS": summ["pipeline_controls_assessment"],
        "PIPELINE_ID": pipe["pipeline_id"],
        "BRANCH_NAME": pipe["branch"],
        "COMMIT_SHA": pipe["commit_sha"],
        "PIPELINE_STATUS": pipe["status"],
        "IMAGE_REFERENCE": pick(
            pipe["image_reference"], summ["detected_image_reference"]
        ),
        "RISK_ACCEPTANCE_DETAILS": add["risk_acceptance_details"],
        "ADDITIONAL_RECOMMENDATIONS": add["additional_recommendations"],
        "RETESTING_PLAN": add["retesting_plan"],
    }
    values = {k: str(v) for k, v in values.items()}

    narr = {}
    for sec, items in helper.items():
        for key, text in items.items():
            narr[f"{sec}.{key}"] = plain_fill(text, values)

    # conclusion.txt -> blocks
    ctext, cmissing = plain_fill(conclusion_txt, values, BRACKET_RE)
    blocks, para, bullets = [], [], []

    def flush():
        nonlocal para, bullets
        if para:
            blocks.append(("p", " ".join(para)))
        if bullets:
            blocks.append(("ul", bullets))
        para, bullets = [], []

    lines = ctext.splitlines()
    if lines and lines[0].strip().upper() == "CONCLUSION":
        lines = lines[1:]
    for ln in lines:
        if not ln.strip():
            flush()
        elif ln.startswith("- "):
            if para:
                flush()
            bullets.append(ln[2:].strip())
        elif bullets and ln.startswith("  "):
            bullets[-1] += " " + ln.strip()
        else:
            if bullets:
                flush()
            para.append(ln.strip())
    flush()

    min_rank = SEV_RANK[min_sev]
    detailed = [f for f in findings if SEV_RANK[f["severity"]] <= min_rank]
    views = {
        f["id"]: finding_view(f, helper["detailed_finding"], values) for f in detailed
    }

    def tool_cell(t):
        if t["status"] == "ok":
            bits = [f"v{t['version']}" if t["version"] else "", t["configuration"]]
            return "; ".join(b for b in bits if b) or "Version not recorded"
        if t["status"] == "error":
            return "Output could not be parsed"
        return "Not run (no JSON output found)"

    plan_rows = [
        (
            r["priority"],
            pick(r["action"], r["suggested_action"]),
            r["owner"],
            r["target_date"],
        )
        for r in data["remediation_plan"]
    ]
    return {
        "data": data,
        "macros": macros,
        "values": values,
        "narr": narr,
        "conclusion_blocks": blocks,
        "conclusion_missing": cmissing,
        "findings": findings,
        "detailed": detailed,
        "views": views,
        "min_sev": min_sev,
        "tools_rows": [
            (t["display_name"], t["purpose"], tool_cell(t)) for t in tools.values()
        ],
        "plan_rows": plan_rows,
        "risk": risk,
        "risk_is_suggested": not meta["overall_risk"],
        "screenshots": screenshots or [],
    }


def finding_view(f: dict, dv: dict, base: dict) -> dict:
    v = dict(base)
    done = f["retest_status"] and f["retest_status"].strip().lower() != "not retested"
    ctx = f["scanner_context"]
    expl = f["exploitability"] or (
        "Exploitation was not manually validated; this finding reflects "
        "scanner-reported potential" + (f" ({ctx})" if ctx else "")
    )
    v.update(
        {
            "DETECTION_ACTIVITY": f["detection_activity"]
            or "automated security analysis",
            "AFFECTED_ASSET": f["affected_asset"] or "the assessed application",
            "ROOT_CAUSE": f["root_cause"] or f["title"],
            "SEVERITY": SEV_LABEL[f["severity"]],
            "FINDING_EVIDENCE_DESCRIPTION": f["evidence_description"] or f["title"],
            "EVIDENCE_SOURCE": f["evidence_source"] or ", ".join(f["source_tools"]),
            "TECHNICAL_IMPACT": f["impact"]
            or CATEGORY_IMPACT.get(f["category"], DEFAULT_IMPACT),
            "EXPLOITABILITY_ASSESSMENT": expl,
            "REMEDIATION_ACTIONS": "the numbered steps below"
            if f["remediation"]
            else "review the finding and apply the vendor or rule guidance",
            "RETEST_STATUS": f["retest_status"],
            "RETEST_DATE": f["retest_date"],
            "RETEST_METHOD": f["retest_method"],
            "RETEST_RESULT": f["retest_result"],
        }
    )
    na = lambda s: s or "N/A"  # noqa: E731
    if done:
        retest = plain_fill(dv["retest"], v)[0]
    else:
        retest = (
            "Not retested. No retest has been performed at the time of reporting; "
            "the remediation status remains unverified."
        )
    score = "" if f["cvss_score"] is None else f"{f['cvss_score']}"
    return {
        "attrs": [
            ("Finding ID", f["id"]),
            ("Title", f["title"]),
            ("Category", f["category"]),
            ("Severity", SEV_LABEL[f["severity"]]),
            ("CVSS version", na(f["cvss_version"])),
            ("CVSS score", na(score)),
            ("CVSS vector", na(f["cvss_vector"])),
            ("Affected asset", na(f["affected_asset"])),
            ("Source tool / test", ", ".join(f["source_tools"]) or "N/A"),
            ("Status", na(f["status"])),
            ("References", ", ".join(f["references"]) or "N/A"),
        ],
        "description": plain_fill(dv["description"], v)[0],
        "tool_description": f["description"],
        "evidence_text": plain_fill(dv["evidence"], v)[0],
        "evidence": f["evidence"],
        "impact": plain_fill(dv["technical_impact"], v)[0],
        "likelihood": plain_fill(dv["likelihood_and_exploitability"], v)[0],
        "remediation_text": plain_fill(dv["remediation"], v)[0],
        "remediation": f["remediation"],
        "retest": retest,
    }


# LaTeX rendering
class Tex:
    def __init__(self, src: str):
        self.t = src
        self.notes: list[str] = []

    def set_macro(self, name: str, value: str):
        pat = re.compile(
            r"(\\newcommand\{\\" + re.escape(name) + r"\}\{)(.*)(\}[ \t]*)$", re.M
        )
        if not pat.search(self.t):
            self.notes.append(f"macro \\{name} not found in template")
            return
        self.t = pat.sub(
            lambda m: m.group(1) + esc(value, wrap=name.endswith("URL")) + m.group(3),
            self.t,
            count=1,
        )

    def replace_placeholder(self, prefix: str, new: str) -> bool:
        pat = re.compile(r"\\placeholder\{" + re.escape(prefix) + r"[^}]*\}")
        if len(pat.findall(self.t)) != 1:
            self.notes.append(f"placeholder starting '{prefix}' not found exactly once")
            return False
        self.t = pat.sub(lambda m: new, self.t, count=1)
        return True

    def _heading(self, title: str):
        m = re.search(
            r"\\(?:chapter|section|subsection)\*?\{" + re.escape(title) + r"\}[^\n]*\n",
            self.t,
        )
        if not m:
            self.notes.append(f"heading '{title}' not found")
        return m

    def insert_after_heading(self, title: str, content: str):
        m = self._heading(title)
        if m:
            self.t = (
                self.t[: m.end()]
                + "\n"
                + content.strip("\n")
                + "\n"
                + self.t[m.end() :]
            )

    def insert_before(self, marker: str, content: str):
        i = self.t.find(marker)
        if i < 0:
            self.notes.append(f"marker '{marker}' not found")
            return
        self.t = self.t[:i] + content.strip("\n") + "\n\n" + self.t[i:]

    def replace_section_body(self, title: str, body: str):
        m = self._heading(title)
        if not m:
            return
        end = re.compile(
            r"^(\\(?:chapter|section|subsection)\*?\{|% -{5,}|\\appendix|\\end\{document\})",
            re.M,
        )
        e = end.search(self.t, m.end())
        stop = e.start() if e else len(self.t)
        self.t = self.t[: m.end()] + body.strip("\n") + "\n\n" + self.t[stop:]

    def replace_rows(self, caption: str, rows: str):
        i = self.t.find("\\caption{" + caption + "}")
        if i < 0:
            self.notes.append(f"table '{caption}' not found")
            return
        a = self.t.find("\\endhead", i)
        b = self.t.find("\\bottomrule", a)
        if a < 0 or b < 0:
            self.notes.append(f"table '{caption}' has no \\endhead/\\bottomrule")
            return
        a = self.t.find("\n", a) + 1
        self.t = self.t[:a] + rows.rstrip("\n") + "\n    " + self.t[b:]

    def fill_row(self, label: str, value: str):
        if not value:
            return
        pat = re.compile(
            r"^(\s*" + re.escape(label) + r" & )\\placeholder\{[^}]*\}( \\\\)$", re.M
        )
        self.t = pat.sub(
            lambda m: m.group(1) + esc(value, wrap=True) + m.group(2), self.t, count=1
        )

    def drop(self, pattern: str):
        self.t, n = re.subn(pattern, "", self.t, count=1)
        if not n:
            self.notes.append(f"scaffolding row not found: {pattern[:40]}")


def tex_blocks(blocks) -> str:
    out = []
    for kind, content in blocks:
        if kind == "p":
            out.append(esc_par(content))
        else:
            out.append(
                "\\begin{itemize}\n"
                + "\n".join(f"    \\item \\relax {esc(i)}" for i in content)
                + "\n\\end{itemize}"
            )
    return "\n\n".join(out)


def tex_finding(f: dict, v: dict) -> str:
    title = f["title"]
    heading = f"\\section{{{f['id']} -- \\texorpdfstring{{{esc(title)}}}{{{pdf_plain(title)}}}}}"
    rows = []
    for label, val in v["attrs"]:
        cell = (
            f"\\severity{{{esc(val)}}}" if label == "Severity" else esc(val, wrap=True)
        )
        rows.append(f"    {label} & {cell} \\\\")
    s = [
        heading,
        "",
        "\\begin{tabularx}{\\textwidth}{@{}p{43mm}Y@{}}",
        "    \\toprule",
        "    \\textbf{Attribute} & \\textbf{Value} \\\\",
        "    \\midrule",
        *rows,
        "    \\bottomrule",
        "\\end{tabularx}",
        "",
        "\\subsection{Description}",
        esc_par(v["description"]),
    ]
    if v["tool_description"]:
        s += ["", "\\textbf{Scanner description.} " + esc_par(v["tool_description"])]
    s += ["", "\\subsection{Evidence}", esc_par(v["evidence_text"])]
    if v["evidence"]:
        s += [
            "",
            "\\begin{lstlisting}",
            ascii_listing(v["evidence"]),
            "\\end{lstlisting}",
        ]
    s += [
        "",
        "\\subsection{Impact}",
        esc_par(v["impact"]),
        "",
        "\\subsection{Likelihood and Exploitability}",
        esc_par(v["likelihood"]),
        "",
        "\\subsection{Remediation}",
        esc_par(v["remediation_text"]),
    ]
    if v["remediation"]:
        s += [
            "\\begin{enumerate}",
            *[f"    \\item \\relax {esc(r)}" for r in v["remediation"]],
            "\\end{enumerate}",
        ]
    s += ["", "\\subsection{Retest Result}", esc_par(v["retest"]), ""]
    return "\n".join(s)


def build_tex(model: dict, tex_src: str) -> tuple[str, list[str]]:
    d, N = model["data"], model["narr"]
    T = Tex(tex_src)

    def narr_ok(key):  # -> text or None when tokens are unresolved
        text, missing = N[key]
        return None if missing else text

    for name, val in model["macros"].items():
        T.set_macro(name, val)

    T.drop(
        r"\n[ \t]*\\placeholder\{VERSION\}[^\n]*\n[ \t]*\\placeholder\{CHANGE DESCRIPTION\} \\\\"
    )
    T.drop(r"\n[ \t]*\\placeholder\{TERM\} & \\placeholder\{DEFINITION\} \\\\")

    T.replace_placeholder(
        "WRITE A SHORT",
        esc_par(N["executive_summary.assessment_results"][0])
        + "\n\n"
        + esc_par(N["executive_summary.overall_risk_assessment"][0]),
    )

    if d["scope"]["out_of_scope"]:
        items = "\n".join(f"    \\item {esc(i)}" for i in d["scope"]["out_of_scope"])
        T.t, n = re.subn(
            r"(\\section\{Out-of-Scope Components\}\s*)\\begin\{itemize\}.*?\\end\{itemize\}",
            lambda m: m.group(1) + "\\begin{itemize}\n" + items + "\n\\end{itemize}",
            T.t,
            count=1,
            flags=re.S,
        )
        if not n:
            T.notes.append("out-of-scope itemize not found")
    t = narr_ok("scope_and_methodology.scope_description")
    if t:
        T.insert_after_heading("Scope", esc_par(t))
    roe = narr_ok("scope_and_methodology.rules_of_engagement")
    if roe:
        T.replace_placeholder(
            "DOCUMENT AUTHORIZATION",
            esc_par(roe)
            + "\n\n"
            + esc_par(N["scope_and_methodology.assessment_limitations"][0]),
        )
    meth = narr_ok("scope_and_methodology.methodology")
    if meth:
        T.replace_section_body("Methodology", esc_par(meth))
    t = narr_ok("scope_and_methodology.tools_and_techniques")
    if t:
        T.insert_after_heading("Tools and Techniques", esc_par(t) + "\n")
    rows = "\n".join(
        f"    {esc(n)} & {esc(p)} & {esc(c, wrap=True)} \\\\"
        for n, p, c in model["tools_rows"]
    )
    T.replace_rows("Assessment tools", rows)

    T.replace_placeholder(
        "DESCRIBE THE PIPELINE FLOW",
        esc_par(N["cicd_security_architecture.pipeline_overview"][0]),
    )
    t = narr_ok("cicd_security_architecture.security_controls_assessment")
    if t:
        T.insert_after_heading("Security Controls by Pipeline Stage", esc_par(t) + "\n")
    t = narr_ok("cicd_security_architecture.pipeline_execution")
    if t:
        T.insert_after_heading("Pipeline Execution Details", esc_par(t) + "\n")
    p, v = d["pipeline"], model["values"]
    T.fill_row("GitLab project", p["gitlab_project"])
    T.fill_row("Execution date", p["execution_date"])
    T.fill_row("Pipeline result", p["status"])
    T.fill_row("Runner / executor", p["runner"])
    T.fill_row("Image reference", v["IMAGE_REFERENCE"])

    if model["findings"]:
        frows = "\n".join(
            f"    {f['id']} & {esc(f['title'], wrap=True)} & {esc(SEV_LABEL[f['severity']])} & "
            f"{esc(f['status'])} & {esc(', '.join(f['source_tools']), wrap=True)} \\\\"
            for f in model["findings"]
        )
    else:
        frows = "    \\multicolumn{5}{@{}l}{No findings were reported by the processed tool outputs.} \\\\"
    T.replace_rows("Summary of security findings", frows)

    a = T.t.find("\\section{F-001")
    c = T.t.find("% Copy the complete F-001")
    if a < 0 or c < 0:
        T.notes.append("detailed-findings template region not found")
    else:
        c = T.t.rfind("% ---", a, c)
        if model["detailed"]:
            body = "\n".join(
                tex_finding(f, model["views"][f["id"]]) for f in model["detailed"]
            )
        else:
            body = "No findings met the detail threshold.\n"
        hidden = len(model["findings"]) - len(model["detailed"])
        if hidden:
            note = (
                f"Findings below {SEV_LABEL[model['min_sev']]} severity ({hidden} in total) are listed in the "
                "findings summary table only. Re-run gen\\_report.py with a lower "
                "\\texttt{-{}-detail-min-severity} to include them here.\n\n"
            )
            body = note + body
        T.t = T.t[:a] + body + "\n" + T.t[c:]

    t = N["risk_rating_method.overall_risk_assessment"][0]
    T.insert_before(
        "\\section{Risk Acceptance}", "\\section{Overall Risk Rating}\n" + esc_par(t)
    )
    t = narr_ok("risk_rating_method.risk_acceptance")
    if t:
        T.replace_placeholder("DOCUMENT THE RISK ACCEPTANCE", esc_par(t))

    T.insert_after_heading(
        "Prioritized Remediation Plan",
        esc_par(N["remediation_recommendations.remediation_overview"][0])
        + "\n\n"
        + esc_par(N["remediation_recommendations.remediation_priorities"][0])
        + "\n",
    )
    prow = "\n".join(
        "    "
        + " & ".join(
            [
                esc(pr),
                esc(act) if act else "\\placeholder{ACTION}",
                esc(own) if own else "\\placeholder{OWNER}",
                esc(dt) if dt else "\\placeholder{DATE}",
            ]
        )
        + " \\\\"
        for pr, act, own, dt in model["plan_rows"]
    )
    T.replace_rows("Remediation plan", prow)
    if d["additional"]["additional_recommendations"]:
        T.insert_before(
            "\\section{Retesting}",
            esc_par(d["additional"]["additional_recommendations"]),
        )
    t = narr_ok("remediation_recommendations.retesting")
    if t:
        T.replace_placeholder("DESCRIBE THE RETEST SCOPE", esc_par(t))

    if not model["conclusion_missing"]:
        T.replace_placeholder(
            "SUMMARIZE THE ASSESSMENT OUTCOME", tex_blocks(model["conclusion_blocks"])
        )
    else:
        T.notes.append(
            "conclusion tokens unresolved: " + ", ".join(model["conclusion_missing"])
        )

    ev = esc_par(N["appendices.pipeline_execution_evidence"][0])
    if d["appendix"]["pipeline_evidence"]:
        ev += (
            "\n\n\\begin{lstlisting}\n"
            + ascii_listing(d["appendix"]["pipeline_evidence"], 60, 6000)
            + "\n\\end{lstlisting}"
        )
    T.replace_placeholder("INCLUDE RELEVANT PIPELINE JOB", ev)

    sb, sg = d["sbom"], d["signing"]
    app = [esc_par(N["appendices.scanner_reports_and_sbom"][0])]
    if d["appendix"]["scanner_reports"]:
        trows = "\n".join(
            f"    {esc(r['tool'])} & {esc(r['file'], wrap=True)} & {r['findings']} & "
            f"\\texttt{{{esc(r['sha256'][:16])}}} \\\\"
            for r in d["appendix"]["scanner_reports"]
        )
        app.append(
            "\\begin{longtable}{@{}p{26mm}p{70mm}p{18mm}p{36mm}@{}}\n"
            "    \\caption{Processed scanner artifacts (SHA-256, first 16 hex characters)}\\\\\n"
            "    \\toprule\n    \\textbf{Tool} & \\textbf{File} & \\textbf{Findings} & \\textbf{SHA-256} \\\\\n"
            "    \\midrule\n    \\endfirsthead\n    \\toprule\n"
            "    \\textbf{Tool} & \\textbf{File} & \\textbf{Findings} & \\textbf{SHA-256} \\\\\n"
            "    \\midrule\n    \\endhead\n"
            + trows
            + "\n    \\bottomrule\n\\end{longtable}"
        )
    if sb["format"]:
        types = ", ".join(
            f"{k}: {v_}" for k, v_ in sorted(sb["components_by_type"].items())
        )
        app.append(
            esc_par(
                f"SBOM: {sb['format']} {sb['spec_version']}, {sb['component_count']} components"
                + (f" ({types})" if types else "")
                + "."
            )
        )
    if sg["verified"] is not None:
        app.append(
            esc_par(
                "Image signature verification: "
                + ("succeeded" if sg["verified"] else "failed")
                + (f" for {sg['image']}" if sg["image"] else "")
                + (f" ({sg['details']})" if sg["details"] else "")
                + "."
            )
        )
    T.replace_placeholder("REFERENCE THE ORIGINAL JSON", "\n\n".join(app))
    if model["screenshots"]:
        T.replace_placeholder("ADD SCREENSHOTS", tex_screenshots(model["screenshots"]))
    T.replace_placeholder(
        "RECORD RELEVANT ASSUMPTIONS",
        esc_par(N["appendices.assumptions_and_limitations"][0]),
    )

    return T.t, T.notes


def unfilled_placeholders(tex: str) -> list[str]:
    body = "\n".join(l for l in tex.splitlines() if not l.lstrip().startswith("%"))
    out = [
        re.sub(r"\s+", " ", m)[:70]
        for m in re.findall(r"\\placeholder\{([^}]*)\}", body)
    ]
    out += [
        f"\\{n} (macro value still '[...]')"
        for n in re.findall(r"\\newcommand\{\\(\w+)\}\{\[[^\n]*\]\}", body)
    ]
    return uniq_list(out)


# PDF: LaTeX engine
def compile_pdf(
    tex_path: Path, texinputs: list | None = None, keep_aux: bool = False
) -> Path:
    tex_path = Path(tex_path).resolve()
    latexmk, pdflatex = shutil.which("latexmk"), shutil.which("pdflatex")
    if not (latexmk or pdflatex):
        raise RuntimeError(
            "no LaTeX engine found (latexmk/pdflatex). Install TeX Live, "
            "or use `--pdf reportlab`."
        )
    env = dict(os.environ)
    if (
        texinputs
    ):  # lets \includegraphics{screenshots/...} resolve outside the build dir
        dirs = "".join(f"{Path(t).resolve()}//{os.pathsep}" for t in texinputs)
        env["TEXINPUTS"] = dirs + env.get("TEXINPUTS", "")
    flags = ["-interaction=nonstopmode", "-halt-on-error", "-file-line-error"]
    cmds = (
        [[latexmk, "-pdf", *flags, tex_path.name]]
        if latexmk
        else [[pdflatex, *flags, tex_path.name]] * 2
    )
    for cmd in cmds:
        r = subprocess.run(
            cmd, cwd=tex_path.parent, env=env, capture_output=True, text=True
        )
        if r.returncode != 0:
            log = tex_path.with_suffix(".log")
            tail = "\n".join(
                (
                    log.read_text(errors="replace") if log.exists() else r.stdout
                ).splitlines()[-40:]
            )
            raise RuntimeError(
                f"LaTeX failed ({Path(cmd[0]).name}); last log lines:\n{tail}"
            )
    pdf = tex_path.with_suffix(".pdf")
    if not keep_aux:
        for ext in (
            ".aux",
            ".log",
            ".toc",
            ".lof",
            ".lot",
            ".out",
            ".fls",
            ".fdb_latexmk",
            ".synctex.gz",
        ):
            tex_path.with_suffix(ext).unlink(missing_ok=True)
    return pdf


# PDF: ReportLab renderer (same data, simpler layout)
def render_reportlab(model: dict, out_pdf: Path) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import (
        Image,
        KeepTogether,
        ListFlowable,
        ListItem,
        PageBreak,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    d, N, m = model["data"], model["narr"], model["macros"]
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    cell = ParagraphStyle("c", parent=body, fontSize=8.5, leading=11)
    cellb = ParagraphStyle("cb", parent=cell, fontName="Helvetica-Bold")
    h1 = ParagraphStyle(
        "h1", parent=ss["Heading1"], fontSize=17, spaceBefore=6, spaceAfter=8
    )
    h2 = ParagraphStyle(
        "h2", parent=ss["Heading2"], fontSize=12.5, spaceBefore=10, spaceAfter=4
    )
    h3 = ParagraphStyle(
        "h3", parent=ss["Heading3"], fontSize=10.5, spaceBefore=6, spaceAfter=2
    )
    mono = ParagraphStyle("m", parent=ss["Code"], fontSize=7.5, leading=9)
    caption_st = ParagraphStyle("cap", parent=body, fontSize=8.5, leading=11)

    def P(text, st=body):
        return Paragraph(xml_escape(sanitize(text)).replace("\n", "<br/>"), st)

    def table(rows, widths, header=True, style_cell=cell):
        data = [
            [
                Paragraph(
                    xml_escape(sanitize(c)).replace("\n", "<br/>"),
                    cellb if (header and i == 0) else style_cell,
                )
                for c in r
            ]
            for i, r in enumerate(rows)
        ]
        t = Table(
            data, colWidths=[w * mm for w in widths], repeatRows=1 if header else 0
        )
        st = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEABOVE", (0, 0), (-1, 0), 0.8, colors.black),
            ("LINEBELOW", (0, -1), (-1, -1), 0.8, colors.black),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]
        if header:
            st.append(("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.black))
        t.setStyle(TableStyle(st))
        return t

    def na(key, placeholder):
        return m.get(key) or f"[{placeholder}]"

    def footer(canv, doc):
        canv.saveState()
        canv.setFont("Helvetica", 8)
        canv.drawString(20 * mm, 10 * mm, m.get("Classification", "[CLASSIFICATION]"))
        canv.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
        canv.restoreState()

    s = []
    s += [
        Spacer(1, 30 * mm),
        P(m.get("ReportTitle", "Penetration Testing Report"), h1),
        P(na("ProjectName", "PROJECT NAME"), h2),
        Spacer(1, 10 * mm),
        table(
            [
                ["Prepared for:", na("ClientName", "CLIENT")],
                ["Prepared by:", na("PreparedBy", "AUTHOR")],
                ["Application:", m.get("TargetApplication", "VAmPI -- Vulnerable API")],
                ["Environment:", na("TargetEnvironment", "ENVIRONMENT")],
                ["Assessment type:", na("TestingType", "TESTING TYPE")],
                [
                    "Assessment dates:",
                    f"{na('AssessmentStart', 'START')} -- {na('AssessmentEnd', 'END')}",
                ],
                ["Report date:", m.get("ReportDate", "")],
                ["Report version:", m.get("ReportVersion", "1.0")],
                ["Status:", na("ReportStatus", "DRAFT / FINAL")],
            ],
            [45, 120],
            header=False,
        ),
        Spacer(1, 25 * mm),
        P(m.get("Classification", "CONFIDENTIAL"), h3),
        P(
            "This document contains security assessment information intended only for the authorized "
            "recipient. Do not distribute without permission."
        ),
        PageBreak(),
    ]

    c = d["summary"]["severity_counts"]
    s += [
        P("1. Executive Summary", h1),
        P("Assessment Overview", h2),
        P(N["executive_summary.assessment_overview"][0]),
        P("Objectives", h2),
        P(N["executive_summary.assessment_objectives"][0]),
        P("Overall Assessment", h2),
        P(
            f"Overall risk rating: {model['risk']}"
            + (
                " (suggested from the finding severities)"
                if model["risk_is_suggested"]
                else ""
            )
        ),
        P(N["executive_summary.assessment_results"][0]),
        P(N["executive_summary.overall_risk_assessment"][0]),
        P("Findings Summary", h2),
        table(
            [
                ["Severity", "Count"],
                ["Critical", c["critical"]],
                ["High", c["high"]],
                ["Medium", c["medium"]],
                ["Low", c["low"]],
                ["Informational", c["informational"]],
                ["Total", c["total"]],
            ],
            [60, 25],
        ),
    ]

    s += [
        PageBreak(),
        P("2. Scope and Methodology", h1),
        P(N["scope_and_methodology.scope_description"][0]),
        P("In-scope components", h2),
        P(N["scope_and_methodology.in_scope_components"][0]),
        P("Out-of-scope components", h2),
        P(N["scope_and_methodology.out_of_scope_components"][0]),
        P("Rules of engagement", h2),
        P(N["scope_and_methodology.rules_of_engagement"][0]),
        P(N["scope_and_methodology.assessment_limitations"][0]),
        P("Methodology", h2),
        P(N["scope_and_methodology.methodology"][0]),
        P("Tools and techniques", h2),
        table(
            [["Tool", "Purpose", "Version / configuration"], *model["tools_rows"]],
            [32, 55, 78],
        ),
    ]

    p = d["pipeline"]
    s += [
        PageBreak(),
        P("3. CI/CD Security Architecture", h1),
        P(N["cicd_security_architecture.pipeline_overview"][0]),
        P(N["cicd_security_architecture.security_controls_assessment"][0]),
        P(N["cicd_security_architecture.pipeline_execution"][0]),
        table(
            [
                ["Field", "Value"],
                ["GitLab project", p["gitlab_project"] or "[PROJECT PATH]"],
                ["Pipeline ID", m.get("PipelineID", "[ID]")],
                ["Pipeline URL", m.get("PipelineURL", "[URL]")],
                ["Branch", m.get("BranchName", "[BRANCH]")],
                ["Commit SHA", m.get("CommitSHA", "[SHA]")],
                ["Execution date", p["execution_date"] or "[DATE]"],
                ["Pipeline result", p["status"] or "[RESULT]"],
                ["Image reference", model["values"]["IMAGE_REFERENCE"] or "[IMAGE]"],
            ],
            [40, 125],
        ),
    ]

    s += [
        PageBreak(),
        P("4. Findings Summary", h1),
        P(N["findings_summary.summary_description"][0]),
        table(
            [
                ["ID", "Finding", "Severity", "Status", "Source"],
                *[
                    [
                        f["id"],
                        f["title"],
                        SEV_LABEL[f["severity"]],
                        f["status"],
                        ", ".join(f["source_tools"]),
                    ]
                    for f in model["findings"]
                ],
            ]
            if model["findings"]
            else [
                [
                    "",
                    "No findings were reported by the processed tool outputs.",
                    "",
                    "",
                    "",
                ]
            ],
            [16, 72, 22, 20, 35],
        ),
        P(N["findings_summary.status_definitions"][0]),
    ]

    s += [PageBreak(), P("5. Detailed Findings", h1)]
    hidden = len(model["findings"]) - len(model["detailed"])
    if hidden:
        s.append(
            P(
                f"Findings below {SEV_LABEL[model['min_sev']]} severity ({hidden}) are listed in the summary only."
            )
        )
    for f in model["detailed"]:
        v = model["views"][f["id"]]
        s += [
            P(f"{f['id']} -- {f['title']}", h2),
            table([["Attribute", "Value"], *v["attrs"]], [40, 125]),
            P("Description", h3),
            P(v["description"]),
        ]
        if v["tool_description"]:
            s.append(P("Scanner description: " + v["tool_description"]))
        s += [P("Evidence", h3), P(v["evidence_text"])]
        if v["evidence"]:
            s.append(Preformatted(ascii_listing(v["evidence"], 14, 1800), mono))
        s += [
            P("Impact", h3),
            P(v["impact"]),
            P("Likelihood and exploitability", h3),
            P(v["likelihood"]),
            P("Remediation", h3),
            P(v["remediation_text"]),
        ]
        if v["remediation"]:
            s.append(
                ListFlowable([ListItem(P(r)) for r in v["remediation"]], bulletType="1")
            )
        s += [P("Retest result", h3), P(v["retest"])]

    s += [
        PageBreak(),
        P("6. Risk Rating and Remediation", h1),
        P(N["risk_rating_method.severity_assessment"][0]),
        P(N["risk_rating_method.overall_risk_assessment"][0]),
        P(N["risk_rating_method.risk_acceptance"][0]),
        P(N["remediation_recommendations.remediation_overview"][0]),
        P(N["remediation_recommendations.remediation_priorities"][0]),
        table(
            [
                ["Priority", "Action", "Owner", "Target date"],
                *[
                    [a, b or "[ACTION]", c_ or "[OWNER]", e or "[DATE]"]
                    for a, b, c_, e in model["plan_rows"]
                ],
            ],
            [24, 80, 30, 30],
        ),
        P(N["remediation_recommendations.cicd_security_improvements"][0]),
        P(N["remediation_recommendations.retesting"][0]),
    ]

    s += [P("7. Conclusion", h1)]
    for kind, content in model["conclusion_blocks"]:
        s.append(
            P(content)
            if kind == "p"
            else ListFlowable([ListItem(P(i)) for i in content], bulletType="bullet")
        )
    s += [
        PageBreak(),
        P("Appendices", h1),
        P("A. Pipeline execution evidence", h2),
        P(N["appendices.pipeline_execution_evidence"][0]),
        P("B. Scanner reports and SBOM", h2),
        P(N["appendices.scanner_reports_and_sbom"][0]),
    ]
    if d["appendix"]["scanner_reports"]:
        s.append(
            table(
                [
                    ["Tool", "File", "Findings", "SHA-256 (16)"],
                    *[
                        [r["tool"], r["file"], r["findings"], r["sha256"][:16]]
                        for r in d["appendix"]["scanner_reports"]
                    ],
                ],
                [28, 80, 18, 39],
            )
        )
    # -- C. screenshots (image + description), same data as the LaTeX appendix
    shot_flow = []
    max_w, max_h = 165 * mm, 150 * mm
    for sh in model["screenshots"]:
        if sh["source"].suffix.lower() not in SHOT_EXTS_REPORTLAB:
            print(
                f"warning: {sh['name']}: ReportLab cannot draw this format; skipped "
                "(use --pdf latex for PDF images)",
                file=sys.stderr,
            )
            continue
        try:
            iw, ih = ImageReader(str(sh["source"])).getSize()
        except Exception as exc:  # noqa: BLE001
            print(
                f"warning: {sh['name']}: cannot read image ({exc}); skipped",
                file=sys.stderr,
            )
            continue
        k = min(max_w / iw, max_h / ih)
        shot_flow.append(
            KeepTogether(
                [
                    Image(
                        str(sh["source"]), width=iw * k, height=ih * k, hAlign="CENTER"
                    ),
                    Spacer(1, 2 * mm),
                    P(f"Figure C.{len(shot_flow) + 1}: {sh['caption']}", caption_st),
                    Spacer(1, 6 * mm),
                ]
            )
        )
    if shot_flow:
        s += [
            P("C. Screenshots and supporting evidence", h2),
            P(
                f"This appendix contains {len(shot_flow)} screenshot(s) collected as supporting evidence "
                "during the assessment. The caption of each figure is its description."
            ),
            *shot_flow,
        ]
    s += [
        P(
            "D. Assumptions and limitations"
            if shot_flow
            else "C. Assumptions and limitations",
            h2,
        ),
        P(N["appendices.assumptions_and_limitations"][0]),
    ]

    out_pdf = Path(out_pdf)
    SimpleDocTemplate(
        str(out_pdf),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=sanitize(m.get("ReportTitle", "Penetration Testing Report")),
    ).build(s, onFirstPage=footer, onLaterPages=footer)
    return out_pdf


# CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    tpl = HERE / "templates"
    ap.add_argument(
        "--data",
        type=Path,
        default=HERE / "output" / "report_data.json",
        help="normalized JSON",
    )
    ap.add_argument("--tex", type=Path, default=tpl / "main.tex", help="LaTeX template")
    ap.add_argument(
        "--narrative",
        type=Path,
        default=tpl / "helper_temp.json",
        help="narrative paragraphs",
    )
    ap.add_argument(
        "--conclusion",
        type=Path,
        default=tpl / "conclusion.txt",
        help="conclusion text",
    )
    ap.add_argument(
        "--out-dir", type=Path, default=HERE / "output", help="output directory"
    )
    ap.add_argument(
        "--assets-dir",
        type=Path,
        action="append",
        default=None,
        help="extra directory searched by LaTeX for \\includegraphics files "
        "(default: reports/pentest, so screenshots/x.png works); repeatable",
    )
    ap.add_argument(
        "--screenshots-dir",
        type=Path,
        default=None,
        help="folder with evidence images; each <name>.png/.jpg/.pdf is described by "
        "<name>.txt in the same folder (default: ../pentest/screenshots, "
        "then ./screenshots)",
    )
    ap.add_argument(
        "--name", default="report", help="output base name (default: report)"
    )
    ap.add_argument(
        "--detail-min-severity",
        choices=SEVERITIES,
        default="medium",
        help="findings at or above this severity get a detailed section (default: medium)",
    )
    ap.add_argument(
        "--pdf",
        nargs="?",
        const="latex",
        choices=["latex", "reportlab"],
        default=None,
        help="also build a PDF (only when given). 'latex' (default) compiles the .tex; "
        "'reportlab' renders the data directly",
    )
    ap.add_argument("--keep-aux", action="store_true", help="keep LaTeX aux/log files")
    args = ap.parse_args(argv)

    for label, p in (
        ("data", args.data),
        ("tex", args.tex),
        ("narrative", args.narrative),
        ("conclusion", args.conclusion),
    ):
        if not p.is_file():
            print(
                f"error: {label} file not found: {p}"
                + ("  (run normalizer.py first)" if label == "data" else ""),
                file=sys.stderr,
            )
            return 2

    data = json.loads(args.data.read_text(encoding="utf-8"))
    helper = json.loads(args.narrative.read_text(encoding="utf-8"))
    args.out_dir.mkdir(parents=True, exist_ok=True)

    # screenshots: image + same-name .txt description -> staged under <out-dir>/screenshots/
    shots, shot_warnings = [], []
    shot_dir = find_screenshot_dir(args.screenshots_dir)
    if args.screenshots_dir and not args.screenshots_dir.is_dir():
        print(
            f"error: screenshots folder not found: {args.screenshots_dir}",
            file=sys.stderr,
        )
        return 2
    if shot_dir:
        shots, shot_warnings = collect_screenshots(shot_dir, args.out_dir)

    model = build_model(
        data,
        helper,
        args.conclusion.read_text(encoding="utf-8"),
        args.detail_min_severity,
        screenshots=shots,
    )
    tex, notes = build_tex(model, args.tex.read_text(encoding="utf-8"))

    tex_path = args.out_dir / f"{args.name}.tex"
    tex_path.write_text(tex, encoding="utf-8")
    print(
        f"wrote {tex_path}  ({len(model['findings'])} findings, {len(model['detailed'])} detailed)"
    )
    if model["risk_is_suggested"]:
        print(
            f"note: overall risk '{model['risk']}' is suggested from severities; set meta.overall_risk to override"
        )
    if shot_dir:
        print(f"screenshots: {len(shots)} image(s) inserted from {shot_dir}")
    else:
        print(
            "screenshots: no screenshots folder found (use --screenshots-dir); "
            "appendix placeholder left as is"
        )
    for n in shot_warnings:
        print("warning:", n)
    for n in notes:
        print("warning:", n)
    left = unfilled_placeholders(tex)
    if left:
        print(f"{len(left)} placeholder(s) left unfilled (no data in the JSON):")
        for item in left:
            print("   -", item)

    if args.pdf:
        try:
            if args.pdf == "latex":
                assets = args.assets_dir or [HERE.parent / "pentest"]
                pdf = compile_pdf(
                    tex_path,
                    texinputs=[args.tex.parent, *assets],
                    keep_aux=args.keep_aux,
                )
            else:
                pdf = render_reportlab(model, args.out_dir / f"{args.name}.pdf")
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
