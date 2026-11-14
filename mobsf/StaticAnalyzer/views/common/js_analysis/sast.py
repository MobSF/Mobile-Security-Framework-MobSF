# -*- coding: utf_8 -*-
"""Tree-sitter rule scanning, URL and secret extraction."""
import logging
import re
import secrets
import time
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.security import sanitize_for_logging
from mobsf.StaticAnalyzer.views.common.js_analysis.constants import (
    CHUNK_LINES,
    JS_SOURCE_EXTS,
    MAX_CHUNK_THRESHOLD_BYTES,
    MAX_SAST_JS_BYTES,
    MAX_URL_SCAN_BYTES,
    SAST_BATCH_BYTES,
)
from mobsf.StaticAnalyzer.views.common.secret_detection import get_secrets
from mobsf.StaticAnalyzer.views.common.shared_func import (
    STRINGS_REGEX,
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.sast_engine import SastEngine

logger = logging.getLogger(__name__)


def extract_js_urls_emails_secrets(file_path, rel_path, urls_list, urls_nf,
                                   emails_nf, secrets_set, extra_strings=None):
    """Extract URLs, emails, and high-entropy secrets from JS or HBC strings."""
    try:
        content = ''
        if file_path and file_path.is_file() and (
                file_path.stat().st_size <= MAX_URL_SCAN_BYTES):
            content = file_path.read_text('utf-8', 'ignore')
        elif extra_strings:
            content = '\n'.join(extra_strings[:20000])
        if not content:
            return
        url_text = content.translate(str.maketrans({"'": '"', '`': '"'}))
        urls, u_nf, e_nf = url_n_email_extract(url_text, rel_path)
        urls_list.extend(urls)
        urls_nf.extend(u_nf)
        emails_nf.extend(e_nf)
        candidate_strings = set()
        if extra_strings:
            for s in extra_strings[:20000]:
                if 8 <= len(s) <= 256 and s[0].isalnum():
                    candidate_strings.add(s)
        else:
            for match in STRINGS_REGEX.finditer(content, re.MULTILINE):
                s = match.group()
                if 8 <= len(s) <= 256 and s[0].isalnum():
                    candidate_strings.add(s)
        if candidate_strings:
            secrets_set.update(get_secrets(candidate_strings))
    except Exception:
        pass


def _cap_finding_lines(findings):
    """Ensure line lists per file stay compact for the source viewer."""
    for details in findings.values():
        files_map = details.get('files', {})
        for fpath, line_str in list(files_map.items()):
            parts = []
            seen = set()
            for tok in str(line_str).split(','):
                tok = tok.strip()
                if tok.isdigit() and tok not in seen:
                    seen.add(tok)
                    parts.append(tok)
                    if len(parts) >= 25:
                        break
            files_map[fpath] = ','.join(parts) if parts else '1'


def _iter_file_chunks(fpath):
    """Yield (line_offset, text) chunks so huge files are never fully loaded."""
    if fpath.stat().st_size <= MAX_CHUNK_THRESHOLD_BYTES:
        yield 0, fpath.read_text('utf-8', 'ignore')
        return
    buf = []
    offset = 0
    with fpath.open(encoding='utf-8', errors='ignore') as fp:
        for line in fp:
            buf.append(line)
            if len(buf) >= CHUNK_LINES:
                yield offset, ''.join(buf)
                offset += len(buf)
                buf = []
    if buf:
        yield offset, ''.join(buf)


def _merge_findings(total, batch_findings, chunk_map):
    """Merge batch findings, mapping chunk paths back to real file lines."""
    for rule, details in batch_findings.items():
        entry = total.setdefault(rule, {**details, 'files': {}})
        for rel, lines in details.get('files', {}).items():
            real, offset = chunk_map.get(rel, (rel, 0))
            if offset:
                lines = ','.join(
                    str(int(tok) + offset)
                    for tok in str(lines).split(',')
                    if tok.strip().isdigit())
            if real in entry['files']:
                entry['files'][real] += ',' + str(lines)
            else:
                entry['files'][real] = str(lines)


def _run_batch(sast, batch, rules_path, findings, chunk_map):
    """Scan one memory-bounded batch; keep earlier results on failure."""
    try:
        _merge_findings(
            findings, sast.run_rules(batch, rules_path), chunk_map)
    except Exception:
        logger.exception('JavaScript SAST batch failed')


def scan_js_files_with_sast(scan_files, rel_base):
    """Run Tree-sitter JS/TS rules via SastEngine on collected files."""
    if not scan_files:
        return {}
    rules_path = (
        Path(settings.BASE_DIR)
        / 'StaticAnalyzer'
        / 'views'
        / 'common'
        / 'rules'
        / 'js_rules.yaml'
    )
    if not rules_path.is_file():
        return {}
    root_prefix = rel_base.as_posix().rstrip('/') + '/'
    options = {
        'match_rules': rules_path.as_posix(),
        'match_extensions': JS_SOURCE_EXTS | {'.bundle', '.jsbundle'},
        'ts_extension_map': {
            '.bundle': 'javascript',
            '.jsbundle': 'javascript',
        },
    }
    sast = SastEngine(options, root_prefix)
    rules = rules_path.as_posix()
    token = secrets.token_hex(4)
    deadline = time.monotonic() + getattr(settings, 'SAST_TIMEOUT', 1800)
    findings, chunk_map = {}, {}
    batch, batch_bytes = [], 0
    for fpath in scan_files:
        try:
            if fpath.stat().st_size > MAX_SAST_JS_BYTES:
                logger.warning(
                    'Skipping JavaScript SAST on file larger than %d MB: %s',
                    MAX_SAST_JS_BYTES // (1024 * 1024),
                    sanitize_for_logging(fpath.name))
                continue
            real_rel = fpath.as_posix().replace(root_prefix, '', 1)
            for idx, (offset, text) in enumerate(_iter_file_chunks(fpath)):
                path = fpath
                if offset:
                    path = fpath.with_name(
                        f'{fpath.stem}.mobsf-{token}-{idx}{fpath.suffix}')
                    chunk_map[path.as_posix().replace(
                        root_prefix, '', 1)] = (real_rel, offset)
                batch.append((path, text))
                batch_bytes += len(text)
                if batch_bytes < SAST_BATCH_BYTES:
                    continue
                if time.monotonic() > deadline:
                    logger.warning('JavaScript SAST time budget exceeded')
                    _cap_finding_lines(findings)
                    return findings
                _run_batch(sast, batch, rules, findings, chunk_map)
                batch, batch_bytes = [], 0
        except OSError:
            continue
    if batch and time.monotonic() <= deadline:
        _run_batch(sast, batch, rules, findings, chunk_map)
    _cap_finding_lines(findings)
    return findings
