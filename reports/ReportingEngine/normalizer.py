#!/usr/bin/env python3


from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
DEFAULT_TEMPLATE = HERE / "templates" / "report_template.json"
DEFAULT_OUTPUT = HERE / "output" / "report_data.json"
DEFAULT_REPORTS = HERE.parent  # all of reports/, minus ReportingnEngine itself

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
SEV_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = worse

# tool key -> (display name, purpose)   (order = order in the report)
TOOLS = {
    "zap": ("OWASP ZAP", "Dynamic API security testing (DAST)"),
    "gitleaks": ("Gitleaks", "Secret detection"),
    "semgrep": ("Semgrep", "Static application security testing"),
    "syft": ("Syft", "SBOM generation"),
    "trivy": ("Trivy", "Container / dependency scanning"),
    "grype": ("Grype", "SBOM vulnerability analysis"),
    "cosign": ("Cosign", "Image signing and verification"),
}
DISPLAY_TO_KEY = {v[0]: k for k, v in TOOLS.items()}

GITLEAKS_SEVERITY = "high"  # gitleaks has no severity of its own
COSIGN_FAILURE_SEVERITY = "medium"  # severity of a failed signature check
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "informational"}
ZAP_CONF = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Confirmed",
}
SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}
OS_PKG_TYPES = {"deb", "rpm", "apk", "alpm", "portage"}
ANALYST_FIELDS = [
    "status",
    "impact",
    "exploitability",
    "retest_status",
    "retest_date",
    "retest_method",
    "retest_result",
]
SECRET_REMEDIATION = [
    "Revoke and rotate the exposed credential immediately.",
    "Remove the secret from the source tree and from git history, and load it "
    "from a secrets manager or a protected CI/CD variable instead.",
    "Keep a secret-scanning gate in the pipeline (and pre-commit) to prevent recurrence.",
]

SKIP_NAMES = {"report_data.json", "report_template.json", "helper_temp.json"}


# small helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def norm_sev(value, default: str = "informational") -> str:
    v = str(value or "").strip().lower()
    aliases = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "informational",
        "informational": "informational",
        "negligible": "informational",
        "unknown": "informational",
        "none": "informational",
    }
    return aliases.get(v, default)


def to_int(v, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def clean_html(s) -> str:
    if not s:
        return ""
    s = re.sub(r"(?i)<\s*br\s*/?>|</p>|</li>", "\n", str(s))
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n", s)
    return s.strip()


def urls_in(text) -> list:
    return uniq(re.findall(r"https?://[^\s<>\"']+", str(text or "")))


def join_list(items: list) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def sev_counts(findings: list) -> dict:
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f["severity"]] += 1
    c["total"] = sum(c.values())
    return c


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json_tolerant(path: Path):
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        dec = json.JSONDecoder()
        for m in re.finditer(r"^[\[{]", text, flags=re.M):
            try:
                obj, _ = dec.raw_decode(text[m.start() :])
                return obj
            except json.JSONDecodeError:
                continue
        raise


def deep_merge(base, over):
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = deep_merge(base[k], v) if k in base else v
        return out
    return base if over is None else over


def set_path(obj: dict, dotted: str, raw: str):
    keys = dotted.split(".")
    cur = obj
    for k in keys[:-1]:
        cur = cur.setdefault(k, {})
    val = raw
    if raw[:1] in "[{" or raw in ("true", "false", "null"):
        try:
            val = json.loads(raw)
        except json.JSONDecodeError:
            pass
    cur[keys[-1]] = val


def target_str(t) -> str:
    if isinstance(t, dict):
        return str(
            t.get("userInput")
            or t.get("imageID")
            or t.get("path")
            or t.get("target")
            or ""
        )
    return str(t or "")


# finding factory / merging
def make_finding(schema: dict, **kw) -> dict:
    f = copy.deepcopy(schema)
    unknown = set(kw) - set(f)
    if unknown:
        raise KeyError(f"unknown finding keys: {unknown}")
    f.update(kw)
    if not f["status"]:
        f["status"] = "Detected"
    return f


def merge_findings(findings: list) -> list:
    merged = {}
    for f in findings:
        key = f["fingerprint"]
        if key not in merged:
            merged[key] = f
            continue
        m = merged[key]
        if SEV_RANK[f["severity"]] < SEV_RANK[m["severity"]]:
            m["severity"] = f["severity"]
        m["source_tools"] = uniq(m["source_tools"] + f["source_tools"])
        m["references"] = uniq(m["references"] + f["references"])
        m["remediation"] = uniq(m["remediation"] + f["remediation"])
        if len(f["description"]) > len(m["description"]):
            m["description"] = f["description"]
        if not m["cvss_vector"] and f["cvss_vector"]:
            m["cvss_vector"], m["cvss_score"], m["cvss_version"] = (
                f["cvss_vector"],
                f["cvss_score"],
                f["cvss_version"],
            )
        m["scanner_context"] = "; ".join(
            uniq(
                [
                    s
                    for s in (
                        m["scanner_context"].split("; ")
                        + f["scanner_context"].split("; ")
                    )
                    if s
                ]
            )
        )
        m["evidence_source"] = ", ".join(
            uniq(
                [
                    s.strip()
                    for s in (m["evidence_source"] + "," + f["evidence_source"]).split(
                        ","
                    )
                ]
            )
        )
        if f["evidence"] and f["evidence"] not in m["evidence"]:
            m["evidence"] = (m["evidence"] + "\n" + f["evidence"]).strip()
        m["detection_activity"] = m["detection_activity"] or f["detection_activity"]
    return list(merged.values())


# parsers: (data, source_name, mk) -> (findings, info)
#   info keys: version, configuration, target, notes[list], sbom{}, signing{}
def parse_zap(data, src, mk):
    findings, targets = [], []
    sites = data.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        name = site.get("@name", "")
        targets.append(name)
        host = urlparse(name).netloc or name
        for a in site.get("alerts") or []:
            insts = a.get("instances") or []
            count = to_int(a.get("count"), len(insts))
            title = a.get("alert") or a.get("name") or "ZAP alert"
            ref = a.get("alertRef") or a.get("pluginid") or title
            sev = ZAP_RISK.get(str(a.get("riskcode", "0")), "informational")
            m = re.search(r"\(([^)]*)\)\s*$", a.get("riskdesc", "") or "")
            confidence = (
                m.group(1) if m else ZAP_CONF.get(str(a.get("confidence", "")), "")
            )

            endpoints = uniq(
                f"{i.get('method', '')} {urlparse(i.get('uri', '')).path or i.get('uri', '')}".strip()
                for i in insts
            )
            if endpoints:
                asset = "; ".join(endpoints[:5])
                if len(endpoints) > 5:
                    asset += f" (+{len(endpoints) - 5} more)"
            else:
                asset = name

            refs = []
            cwe = str(a.get("cweid", "")).strip()
            if cwe not in ("", "0", "-1"):
                refs.append(f"CWE-{cwe}")
            wasc = str(a.get("wascid", "")).strip()
            if wasc not in ("", "0", "-1"):
                refs.append(f"WASC-{wasc}")
            refs.append(f"ZAP rule {a.get('pluginid', ref)}")
            refs += urls_in(a.get("reference"))[:3]

            desc = clean_html(a.get("desc"))
            other = clean_html(a.get("otherinfo"))
            if other:
                desc = (desc + "\nAdditional information: " + other).strip()

            shown = insts[:10]
            lines = []
            for i in shown:
                parts = [f"{i.get('method', '')} {i.get('uri', '')}".strip()]
                for label, key in (
                    ("param", "param"),
                    ("attack", "attack"),
                    ("evidence", "evidence"),
                ):
                    if i.get(key):
                        parts.append(f"{label}={i[key]}")
                lines.append(" | ".join(parts)[:300])
            if count > len(shown):
                lines.append(f"... {count - len(shown)} more instance(s) not shown")

            findings.append(
                mk(
                    fingerprint=f"api|{ref}|{host}",
                    title=title,
                    category="API",
                    severity=sev,
                    rule_id=str(a.get("pluginid", ref)),
                    affected_asset=asset,
                    source_tools=[TOOLS["zap"][0]],
                    references=uniq(refs),
                    description=desc,
                    scanner_context=f"Scanner confidence: {confidence}"
                    if confidence
                    else "",
                    detection_activity="automated dynamic API scanning with OWASP ZAP",
                    root_cause=title,
                    evidence_description=f"ZAP alert {ref} with {count} reported instance(s)",
                    evidence_source=src,
                    evidence="\n".join(lines),
                    instance_count=count,
                    remediation=[
                        l for l in clean_html(a.get("solution")).split("\n") if l
                    ][:4],
                )
            )
    return findings, {
        "version": str(data.get("@version", "")),
        "target": ", ".join(uniq(targets)),
        "configuration": "zap-api-scan.py (OpenAPI definition scan)",
    }


def parse_gitleaks(data, src, mk):
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or []
    findings = []
    for r in data:
        rule = r.get("RuleID", "")
        desc = r.get("Description") or rule
        file_, line = r.get("File", ""), r.get("StartLine", "")
        secret_len = len(r.get("Secret") or "")
        # NEVER copy "Secret" / "Match" into the report data.
        ev = [f"File: {file_}:{line}", f"Rule: {rule}"]
        if r.get("Commit"):
            ev.append(f"Commit: {str(r['Commit'])[:12]}")
        if r.get("Entropy"):
            ev.append(f"Entropy: {r['Entropy']}")
        ev.append(
            f"Secret value: [REDACTED] ({secret_len} characters)"
            if secret_len
            else "Secret value: [REDACTED]"
        )
        findings.append(
            mk(
                fingerprint=f"secret|{rule}|{file_}:{line}|{r.get('Fingerprint', '')}",
                title=f"Hardcoded secret: {desc}",
                category="SECRETS",
                severity=GITLEAKS_SEVERITY,
                rule_id=rule,
                affected_asset=f"{file_}:{line}",
                source_tools=[TOOLS["gitleaks"][0]],
                references=uniq([rule] + as_list(r.get("Tags"))),
                description=f"Gitleaks rule '{rule}' matched a value that looks like a credential.",
                detection_activity="secret detection with Gitleaks",
                root_cause="a credential committed to the repository",
                evidence_description=f"Gitleaks rule {rule} match in {file_}",
                evidence_source=src,
                evidence="\n".join(ev),
                instance_count=1,
                remediation=list(SECRET_REMEDIATION),
            )
        )
    return findings, {"configuration": "gitleaks detect (JSON report)"}


def parse_semgrep(data, src, mk):
    findings = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cid = r.get("check_id", "")
        path = r.get("path", "")
        line = (r.get("start") or {}).get("line", "")
        refs = uniq(
            as_list(meta.get("cwe"))
            + as_list(meta.get("owasp"))
            + as_list(meta.get("references"))[:2]
            + [cid]
        )
        ev = [f"{path}:{line}"]
        code = extra.get("lines", "")
        if code and "requires login" not in code:
            ev.append(code.strip()[:500])
        rem = (
            [f"Suggested fix: {extra['fix']}"]
            if extra.get("fix")
            else [
                "Apply the guidance in the rule description to the flagged code and re-run the scan."
            ]
        )
        findings.append(
            mk(
                fingerprint=f"sast|{cid}|{path}:{line}",
                title=cid.rsplit(".", 1)[-1] or cid,
                category="SAST",
                severity=SEMGREP_SEVERITY.get(
                    str(extra.get("severity", "")).upper(), "low"
                ),
                rule_id=cid,
                affected_asset=f"{path}:{line}",
                source_tools=[TOOLS["semgrep"][0]],
                references=refs,
                description=extra.get("message", ""),
                scanner_context="; ".join(
                    f"{k.capitalize()}: {meta[k]}"
                    for k in ("confidence", "impact", "likelihood")
                    if meta.get(k)
                ),
                detection_activity="static application security testing with Semgrep",
                root_cause=extra.get("message", "").split(". ")[0][:200],
                evidence_description=f"Semgrep rule {cid}",
                evidence_source=src,
                evidence="\n".join(ev),
                instance_count=1,
                remediation=rem,
            )
        )
    scanned = len((data.get("paths") or {}).get("scanned") or [])
    errs = len(data.get("errors") or [])
    cfg = f"{scanned} files scanned" if scanned else ""
    if errs:
        cfg += f"{'; ' if cfg else ''}{errs} scan error(s) reported"
    return findings, {"version": str(data.get("version", "")), "configuration": cfg}


def _trivy_cvss(cvss: dict):
    best = (None, "", "")
    for v in (cvss or {}).values():
        score = to_float(v.get("V3Score"))
        if score is not None and (best[0] is None or score > best[0]):
            vec = v.get("V3Vector", "")
            ver = (re.match(r"CVSS:(\d\.\d)", vec) or [None, "3"])[1]
            best = (score, vec, ver)
    return best


def parse_trivy(data, src, mk):
    findings = []
    tool = TOOLS["trivy"][0]
    for res in data.get("Results") or []:
        target, cls = res.get("Target", ""), res.get("Class", "")
        category = "CONTAINER" if cls in ("os-pkgs", "config") else "DEPENDENCY"
        for v in res.get("Vulnerabilities") or []:
            vid, pkg = v.get("VulnerabilityID", ""), v.get("PkgName", "")
            inst, fixed = v.get("InstalledVersion", ""), v.get("FixedVersion", "")
            score, vec, ver = _trivy_cvss(v.get("CVSS"))
            desc = ". ".join(x for x in (v.get("Title"), v.get("Description")) if x)
            rem = (
                [f"Upgrade {pkg} from {inst} to {fixed} or later."]
                if fixed
                else [
                    "No fixed version is reported yet; track the upstream advisory and apply "
                    "compensating controls or replace the package."
                ]
            )
            findings.append(
                mk(
                    fingerprint=f"pkg|{vid}|{pkg}|{inst}",
                    title=f"{vid} in {pkg} {inst}".strip(),
                    category=category,
                    severity=norm_sev(v.get("Severity")),
                    rule_id=vid,
                    cvss_version=ver if score is not None else "",
                    cvss_score=score,
                    cvss_vector=vec,
                    affected_asset=f"{pkg} {inst} ({target})",
                    source_tools=[tool],
                    references=uniq(
                        [vid]
                        + as_list(v.get("CweIDs"))
                        + [v.get("PrimaryURL")]
                        + as_list(v.get("References"))[:2]
                    ),
                    description=desc,
                    detection_activity="container image and dependency scanning with Trivy",
                    root_cause=f"a known vulnerability in {pkg} {inst}",
                    evidence_description=f"Trivy reported {vid} for {pkg} {inst}",
                    evidence_source=src,
                    instance_count=1,
                    remediation=rem,
                    evidence=f"Target: {target}\nPackage: {pkg} {inst}\nFixed version: {fixed or 'none reported'}",
                )
            )
        for mc in res.get("Misconfigurations") or []:
            mid = mc.get("ID") or mc.get("AVDID") or ""
            findings.append(
                mk(
                    fingerprint=f"misconf|{mid}|{target}",
                    title=mc.get("Title") or mid,
                    category="CONTAINER",
                    severity=norm_sev(mc.get("Severity")),
                    rule_id=mid,
                    affected_asset=target,
                    source_tools=[tool],
                    references=uniq(
                        [mid, mc.get("PrimaryURL")] + as_list(mc.get("References"))[:2]
                    ),
                    description=". ".join(
                        x for x in (mc.get("Description"), mc.get("Message")) if x
                    ),
                    detection_activity="configuration scanning with Trivy",
                    root_cause=mc.get("Message", "") or mc.get("Title", ""),
                    evidence_description=f"Trivy misconfiguration check {mid}",
                    evidence_source=src,
                    instance_count=1,
                    remediation=[mc["Resolution"]] if mc.get("Resolution") else [],
                    evidence=f"Target: {target}",
                )
            )
        for sc in res.get("Secrets") or []:  # "Match" deliberately not copied
            rid = sc.get("RuleID", "")
            findings.append(
                mk(
                    fingerprint=f"secret|{rid}|{target}:{sc.get('StartLine', '')}",
                    title=f"Hardcoded secret: {sc.get('Title') or rid}",
                    category="SECRETS",
                    severity=norm_sev(sc.get("Severity"), "high"),
                    rule_id=rid,
                    affected_asset=f"{target}:{sc.get('StartLine', '')}",
                    source_tools=[tool],
                    references=[rid],
                    description="Trivy secret scanner matched a credential-like value.",
                    detection_activity="secret scanning with Trivy",
                    root_cause="a credential embedded in the image",
                    evidence_description=f"Trivy secret rule {rid}",
                    evidence_source=src,
                    instance_count=1,
                    evidence=f"File: {target}:{sc.get('StartLine', '')}\nSecret value: [REDACTED]",
                    remediation=list(SECRET_REMEDIATION),
                )
            )
    ver = (
        (data.get("Trivy") or {}).get("Version")
        or (data.get("Metadata") or {}).get("TrivyVersion")
        or ""
    )
    return findings, {
        "version": str(ver),
        "target": data.get("ArtifactName", ""),
        "configuration": f"artifact type: {data.get('ArtifactType', 'n/a')}",
    }


def _grype_cvss(vuln: dict, related: list):
    best = (None, "", "")
    for v in [vuln] + related:
        for c in v.get("cvss") or []:
            score = to_float((c.get("metrics") or {}).get("baseScore"))
            if score is not None and (best[0] is None or score > best[0]):
                best = (score, c.get("vector", ""), str(c.get("version", "")))
    return best


def parse_grype(data, src, mk):
    findings = []
    for m in data.get("matches") or []:
        v, art = m.get("vulnerability") or {}, m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        vid = v.get("id", "")
        primary = (
            vid
            if vid.startswith("CVE-")
            else next(
                (
                    r.get("id")
                    for r in related
                    if str(r.get("id", "")).startswith("CVE-")
                ),
                vid,
            )
        )
        name, ver = art.get("name", ""), art.get("version", "")
        fix = v.get("fix") or {}
        fixes = fix.get("versions") or []
        score, vec, cv = _grype_cvss(v, related)
        ctx = []
        if v.get("epss"):
            ctx.append(f"EPSS {to_float(v['epss'][0].get('epss')) or 0:.4f}")
        if v.get("knownExploited"):
            ctx.append("listed in the CISA Known Exploited Vulnerabilities catalog")
        desc = v.get("description") or next(
            (r.get("description") for r in related if r.get("description")), ""
        )
        loc = ((art.get("locations") or [{}])[0]).get("path", "")
        rem = (
            [f"Upgrade {name} from {ver} to {fixes[0]} or later."]
            if fixes
            else [
                "No fixed version is reported yet; track the upstream advisory and apply "
                "compensating controls or replace the package."
            ]
        )
        findings.append(
            mk(
                fingerprint=f"pkg|{primary}|{name}|{ver}",
                title=f"{primary} in {name} {ver}".strip(),
                category="CONTAINER"
                if art.get("type") in OS_PKG_TYPES
                else "DEPENDENCY",
                severity=norm_sev(v.get("severity")),
                rule_id=primary,
                cvss_version=cv if score is not None else "",
                cvss_score=score,
                cvss_vector=vec,
                affected_asset=f"{name} {ver}" + (f" ({loc})" if loc else ""),
                source_tools=[TOOLS["grype"][0]],
                references=uniq(
                    [primary, vid]
                    + [r.get("id") for r in related]
                    + as_list(v.get("urls"))[:2]
                ),
                description=desc,
                scanner_context="; ".join(ctx),
                detection_activity="SBOM vulnerability analysis with Grype",
                root_cause=f"a known vulnerability in {name} {ver}",
                evidence_description=f"Grype matched {primary} against {name} {ver}",
                evidence_source=src,
                instance_count=1,
                remediation=rem,
                evidence=(
                    f"Package: {name} {ver} ({art.get('type', '')})\nPURL: {art.get('purl', '')}\n"
                    f"Location: {loc}\nFix state: {fix.get('state', 'unknown')}"
                ),
            )
        )
    desc = data.get("descriptor") or {}
    cfg = ""
    if (desc.get("db") or {}).get("status", {}):
        db = desc["db"]["status"]
        cfg = (
            f"vulnerability DB built {db.get('built', 'n/a')}"
            if isinstance(db, dict)
            else ""
        )
    return findings, {
        "version": str(desc.get("version", "")),
        "configuration": cfg,
        "target": target_str((data.get("source") or {}).get("target")),
    }


def parse_syft(data, src, mk):
    sbom = {
        "format": "",
        "spec_version": "",
        "generator": "",
        "component_count": 0,
        "components_by_type": {},
        "source_files": [src],
    }
    version, target = "", ""
    if data.get("bomFormat") == "CycloneDX":
        comps = data.get("components") or []
        tools = (data.get("metadata") or {}).get("tools") or []
        if isinstance(tools, dict):
            tools = tools.get("components") or []
        gen = next((t for t in tools if isinstance(t, dict)), {})
        version = str(gen.get("version", ""))
        sbom.update(
            format="CycloneDX",
            spec_version=str(data.get("specVersion", "")),
            generator=str(gen.get("name", "")),
            component_count=len(comps),
            components_by_type=dict(Counter(c.get("type", "unknown") for c in comps)),
        )
    elif "spdxVersion" in data:
        pk = data.get("packages") or []
        creators = (data.get("creationInfo") or {}).get("creators") or []
        sbom.update(
            format="SPDX",
            spec_version=str(data["spdxVersion"]),
            generator=", ".join(creators),
            component_count=len(pk),
            components_by_type=dict(Counter("package" for _ in pk)),
        )
    else:  # syft-json
        arts = data.get("artifacts") or []
        d = data.get("descriptor") or {}
        version = str(d.get("version", ""))
        target = target_str((data.get("source") or {}).get("target"))
        sbom.update(
            format="syft-json",
            spec_version=str((data.get("schema") or {}).get("version", "")),
            generator=str(d.get("name", "syft")),
            component_count=len(arts),
            components_by_type=dict(Counter(a.get("type", "unknown") for a in arts)),
        )
    cfg = f"{sbom['format']} {sbom['spec_version']}, {sbom['component_count']} components".strip()
    return [], {
        "version": version,
        "configuration": cfg,
        "target": target,
        "sbom": sbom,
    }


def parse_cosign(data, src, mk):
    entries = [e for e in as_list(data) if isinstance(e, dict)]
    signing = {
        "signed": None,
        "verified": None,
        "image": "",
        "digest": "",
        "identity": "",
        "issuer": "",
        "details": "",
        "source_files": [src],
    }
    verdict = None
    for e in entries:
        crit = e.get("critical")
        if crit:
            verdict = True
            signing["image"] = (crit.get("identity") or {}).get(
                "docker-reference"
            ) or signing["image"]
            signing["digest"] = (crit.get("image") or {}).get(
                "docker-manifest-digest"
            ) or signing["digest"]
            opt = e.get("optional") or {}
            signing["identity"] = (
                opt.get("Subject") or opt.get("subject") or signing["identity"]
            )
            signing["issuer"] = (
                opt.get("Issuer") or opt.get("issuer") or signing["issuer"]
            )
        for key in ("verified", "signed"):
            if key in e:
                verdict = bool(e[key])
        if e.get("error"):
            signing["details"] = str(e["error"])
        if e.get("image") and not signing["image"]:
            signing["image"] = str(e["image"])
    signing["verified"] = verdict
    signing["signed"] = verdict
    if verdict is True:
        signing["details"] = (
            signing["details"] or f"{len(entries)} signature(s) verified"
        )
    findings = []
    notes = []
    if verdict is False:
        findings.append(
            mk(
                fingerprint="supply|cosign-verify|image",
                title="Container image signature verification failed",
                category="SUPPLY CHAIN",
                severity=COSIGN_FAILURE_SEVERITY,
                rule_id="cosign-verify",
                affected_asset=signing["image"] or "container image",
                source_tools=[TOOLS["cosign"][0]],
                references=["cosign verify"],
                description="Cosign could not verify a valid signature for the image: "
                + (signing["details"] or "no details provided."),
                detection_activity="image signature verification with Cosign",
                root_cause="a missing, invalid or untrusted image signature",
                evidence_description="Cosign verification result",
                evidence_source=src,
                evidence=signing["details"],
                instance_count=1,
                remediation=[
                    "Sign the image in the pipeline (cosign sign) and publish the signature with the image.",
                    "Verify signatures before deployment using an explicit trust policy "
                    "(certificate identity and OIDC issuer, or a public key).",
                    "Block deployment of unsigned or unverifiable images.",
                ],
            )
        )
    elif verdict is None:
        notes.append("unrecognized cosign output format; no verdict recorded")
    return findings, {
        "target": signing["image"],
        "signing": signing,
        "notes": notes,
        "configuration": "cosign verify",
    }


PARSERS = {
    "zap": parse_zap,
    "gitleaks": parse_gitleaks,
    "semgrep": parse_semgrep,
    "syft": parse_syft,
    "trivy": parse_trivy,
    "grype": parse_grype,
    "cosign": parse_cosign,
}


# detection
def sniff(data):
    if isinstance(data, dict):
        if "site" in data and any(
            k in data for k in ("@version", "@programName", "@generated")
        ):
            return "zap"
        if "results" in data and any(k in data for k in ("paths", "errors")):
            return "semgrep"
        if "matches" in data and any(k in data for k in ("descriptor", "source")):
            return "grype"
        if "Results" in data or ("SchemaVersion" in data and "ArtifactName" in data):
            return "trivy"
        if (
            data.get("bomFormat") == "CycloneDX"
            or "spdxVersion" in data
            or (
                "artifacts" in data
                and any(k in data for k in ("schema", "descriptor", "source"))
            )
        ):
            return "syft"
        if "critical" in data or "verified" in data:
            return "cosign"
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        if "RuleID" in data[0]:
            return "gitleaks"
        if "critical" in data[0]:
            return "cosign"
    return None


def name_hint(path: Path):
    n = path.name.lower()
    for key in TOOLS:
        if key in n:
            return key
    if "sbom" in n:
        return "syft"
    if "secret" in n or "leak" in n:
        return "gitleaks"
    return None


# derived text
def build_main_issues(findings: list) -> str:
    if not findings:
        return "the absence of reported findings in the processed tool outputs"
    notable = [f for f in findings if SEV_RANK[f["severity"]] <= SEV_RANK["medium"]]
    pkg_cats = {"DEPENDENCY", "CONTAINER"}
    pkg = [f for f in notable if f["category"] in pkg_cats]
    other = [f for f in notable if f["category"] not in pkg_cats]
    titles = uniq(f["title"] for f in other)
    parts = titles[:4]
    if len(titles) > 4:
        parts.append(
            f"{len(titles) - 4} further application, secret or supply-chain weaknesses"
        )
    if pkg:
        hi = sum(1 for f in pkg if f["severity"] in ("critical", "high"))
        parts.append(
            f"{len(pkg)} vulnerable software packages or container components "
            f"({hi} Critical/High)"
        )
    return (
        join_list(parts)
        if parts
        else "low-severity and informational observations only"
    )


def build_pipeline_assessment(tools: dict, signing: dict, total: int):
    ok = [t["display_name"] for t in tools.values() if t["status"] == "ok"]
    miss = [t["display_name"] for t in tools.values() if t["status"] == "not_run"]
    err = [t["display_name"] for t in tools.values() if t["status"] == "error"]
    n = len(tools)
    tail = ""
    if miss:
        tail += f"; no JSON output was found for {join_list(miss)}"
    if err:
        tail += f"; the output of {join_list(err)} could not be parsed"
    if signing.get("verified") is True:
        tail += "; image signature verification succeeded"
    elif signing.get("verified") is False:
        tail += "; image signature verification failed"
    tail += f". The processed outputs contained {total} finding(s) in total"
    a = f"output was available for {len(ok)} of {n} security controls ({join_list(ok) or 'none'}){tail}"
    b = f"produced usable output for {len(ok)} of {n} expected tools ({join_list(ok) or 'none'}){tail}"
    return a, b


def build_remediation_suggestions(findings: list, plan: list) -> None:
    def ids(sevs):
        return [f["id"] for f in findings if f["severity"] in sevs]

    hi, med, low = (
        ids(("critical", "high")),
        ids(("medium",)),
        ids(("low", "informational")),
    )

    def phrase(n, label, ids_):
        shown = ", ".join(ids_[:5]) + (" ..." if len(ids_) > 5 else "")
        return (
            f"Remediate {n} {label} finding(s) ({shown})."
            if n
            else f"No {label} findings were reported; no action required at this priority."
        )

    sugg = {
        "Immediate": phrase(len(hi), "Critical/High", hi),
        "Short term": phrase(len(med), "Medium", med),
        "Medium term": phrase(len(low), "Low/Informational", low)
        if low
        else "No Low/Informational findings were reported.",
        "Long term": "Strengthen the CI/CD pipeline: enforce failure thresholds, retain SBOM and scan "
        "artifacts, verify image signatures before deployment and re-run scans after fixes.",
    }
    for row in plan:
        row["suggested_action"] = sugg.get(
            row.get("priority", ""), row.get("suggested_action", "")
        )


# main
def discover(reports_dir: Path):
    for p in sorted(reports_dir.rglob("*.json")):
        if p.name in SKIP_NAMES or not p.is_file():
            continue
        # On a default scan of reports/, never ingest our own templates/output/test_data.
        if HERE in p.resolve().parents and not reports_dir.resolve().is_relative_to(
            HERE
        ):
            continue
        yield p


def normalize(reports_dir: Path, template: dict, previous: dict, env: dict) -> dict:
    schema = template["finding_schema"]
    mk = lambda **kw: make_finding(schema, **kw)  # noqa: E731

    out = deep_merge(template, previous)
    out["finding_schema"] = schema
    out["generated_at"] = now_iso()

    state = {
        k: {
            "files": [],
            "version": "",
            "configuration": "",
            "target": "",
            "notes": [],
            "status": "not_run",
        }
        for k in TOOLS
    }
    all_findings, unrecognized, errors, reports, mtimes = [], [], [], [], []
    sbom, signing = None, None

    for path in discover(reports_dir):
        rel = str(path.relative_to(reports_dir))
        try:
            data = load_json_tolerant(path)
        except (json.JSONDecodeError, OSError) as exc:
            unrecognized.append(rel)
            errors.append(f"{rel}: not valid JSON ({exc})")
            continue
        tool = sniff(data) or name_hint(path)
        if not tool:
            unrecognized.append(rel)
            continue
        st = state[tool]
        try:
            findings, info = PARSERS[tool](data, rel, mk)
        except Exception as exc:  # noqa: BLE001 - keep going, report it
            st["status"] = "error"
            st["notes"].append(f"{rel}: parse error: {exc}")
            errors.append(f"{rel}: {tool} parse error: {exc!r}")
            continue
        st["files"].append(rel)
        if st["status"] != "error":
            st["status"] = "ok"
        for k in ("version", "configuration", "target"):
            st[k] = st[k] or info.get(k, "")
        st["notes"] += info.get("notes", [])
        sbom = info.get("sbom") or sbom
        signing = info.get("signing") or signing
        all_findings += findings
        mtimes.append(path.stat().st_mtime)
        reports.append(
            {
                "tool": TOOLS[tool][0],
                "file": rel,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_of(path),
                "findings": len(findings),
            }
        )

    findings = merge_findings(all_findings)
    cat_order = {
        "API": 0,
        "SECRETS": 1,
        "SAST": 2,
        "DEPENDENCY": 3,
        "CONTAINER": 4,
        "SUPPLY CHAIN": 5,
    }
    findings.sort(
        key=lambda f: (
            SEV_RANK[f["severity"]],
            cat_order.get(f["category"], 9),
            f["title"].lower(),
            f["fingerprint"],
        )
    )
    prev = {f.get("fingerprint"): f for f in previous.get("findings", [])}
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"
        old = prev.get(f["fingerprint"])
        if old:
            for k in ANALYST_FIELDS:
                if old.get(k):
                    f[k] = old[k]
    out["findings"] = findings

    for key, (display, purpose) in TOOLS.items():
        t, st = out["tools"][key], state[key]
        mine = [f for f in findings if display in f["source_tools"]]
        t["display_name"], t["purpose"] = display, purpose
        t["status"] = st["status"]
        t["source_files"] = st["files"]
        t["version"] = st["version"] or t.get("version", "")
        t["configuration"] = st["configuration"] or t.get("configuration", "")
        t["target"] = st["target"]
        t["notes"] = "; ".join(st["notes"])
        t["severity_counts"] = sev_counts(mine)
        t["finding_count"] = len(mine)

    if sbom:
        out["sbom"] = sbom
    else:
        out["sbom"] = copy.deepcopy(template["sbom"])
    if signing:
        out["signing"] = signing
    else:
        out["signing"] = copy.deepcopy(template["signing"])

    counts = sev_counts(findings)
    s = out["summary"]
    s["severity_counts"] = counts
    s["counts_by_category"] = dict(Counter(f["category"] for f in findings))
    s["counts_by_tool"] = {
        t["display_name"]: t["finding_count"]
        for t in out["tools"].values()
        if t["status"] == "ok"
    }
    s["main_security_issues"] = build_main_issues(findings)
    s["pipeline_security_assessment"], s["pipeline_controls_assessment"] = (
        build_pipeline_assessment(out["tools"], out["signing"], counts["total"])
    )
    worst = next((x for x in SEVERITIES if counts[x]), None)
    s["suggested_overall_risk"] = (
        SEV_LABEL[worst]
        if worst and worst != "informational"
        else ("Informational" if worst else "None identified")
    )
    s["suggested_risk_rationale"] = (
        f"the highest severity observed was {SEV_LABEL[worst]} "
        f"({counts['critical']} Critical, {counts['high']} High, {counts['medium']} Medium, "
        f"{counts['low']} Low, {counts['informational']} Informational) across "
        f"{len(s['counts_by_tool'])} tool(s)"
        if worst
        else "no findings were reported by the processed tools"
    )
    if mtimes:
        s["scan_window_start"] = (
            datetime.fromtimestamp(min(mtimes), timezone.utc).date().isoformat()
        )
        s["scan_window_end"] = (
            datetime.fromtimestamp(max(mtimes), timezone.utc).date().isoformat()
        )
    s["detected_target"] = out["tools"]["zap"]["target"]
    s["detected_image_reference"] = next(
        (
            out["tools"][k]["target"]
            for k in ("cosign", "trivy", "grype", "syft")
            if out["tools"][k]["target"]
        ),
        "",
    )

    p = out["pipeline"]
    for field, var in (
        ("pipeline_id", "CI_PIPELINE_ID"),
        ("pipeline_url", "CI_PIPELINE_URL"),
        ("commit_sha", "CI_COMMIT_SHA"),
        ("branch", "CI_COMMIT_REF_NAME"),
        ("repository_url", "CI_PROJECT_URL"),
        ("gitlab_project", "CI_PROJECT_PATH"),
        ("runner", "CI_RUNNER_DESCRIPTION"),
    ):
        if not p[field] and env.get(var):
            p[field] = env[var]
    if not out["meta"]["project_name"] and env.get("CI_PROJECT_TITLE"):
        out["meta"]["project_name"] = env["CI_PROJECT_TITLE"]

    # remediation plan: keep owners/dates, refresh the suggestions
    tmpl_rows = {r["priority"]: r for r in template["remediation_plan"]}
    plan = []
    for row in out["remediation_plan"]:
        plan.append(deep_merge(tmpl_rows.get(row.get("priority"), {}), row))
    for pr, r in tmpl_rows.items():
        if pr not in {x["priority"] for x in plan}:
            plan.append(copy.deepcopy(r))
    build_remediation_suggestions(findings, plan)
    out["remediation_plan"] = plan

    out["appendix"]["scanner_reports"] = reports
    out["normalizer"] = {
        "reports_dir": str(reports_dir),
        "unrecognized_files": unrecognized,
        "errors": errors,
    }
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--reports-dir",
        type=Path,
        default=DEFAULT_REPORTS,
        help="directory scanned recursively for tool JSON output (default: %(default)s)",
    )
    ap.add_argument(
        "--template",
        type=Path,
        default=DEFAULT_TEMPLATE,
        help="blank JSON template defining the keys (default: %(default)s)",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="normalized JSON to write (default: %(default)s)",
    )
    ap.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="PATH=VALUE",
        help="set a manual field, e.g. meta.client_name=ACME (repeatable)",
    )
    args = ap.parse_args(argv)

    if not args.reports_dir.is_dir():
        print(f"error: reports dir not found: {args.reports_dir}", file=sys.stderr)
        return 2
    template = json.loads(args.template.read_text(encoding="utf-8"))
    previous = {}
    if args.output.exists() and args.output.resolve() != args.template.resolve():
        try:
            previous = json.loads(args.output.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(
                f"warning: ignoring unreadable previous output {args.output}",
                file=sys.stderr,
            )

    out = normalize(args.reports_dir.resolve(), template, previous, os.environ)
    for item in args.set:
        if "=" not in item:
            print(f"error: --set expects PATH=VALUE, got {item!r}", file=sys.stderr)
            return 2
        k, v = item.split("=", 1)
        set_path(out, k.strip(), v)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    tmp.replace(args.output)

    print(f"wrote {args.output}")
    for key, t in out["tools"].items():
        print(
            f"  {t['display_name']:<10} {t['status']:<8} files={len(t['source_files'])} "
            f"findings={t['finding_count']}"
        )
    c = out["summary"]["severity_counts"]
    print(
        f"  total findings: {c['total']}  (C={c['critical']} H={c['high']} M={c['medium']} "
        f"L={c['low']} I={c['informational']})"
    )
    if out["normalizer"]["unrecognized_files"]:
        print(
            "  unrecognized JSON files:",
            ", ".join(out["normalizer"]["unrecognized_files"]),
        )
    for e in out["normalizer"]["errors"]:
        print("  error:", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
