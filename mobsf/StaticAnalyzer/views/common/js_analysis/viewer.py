# -*- coding: utf_8 -*-
"""Minified JavaScript formatting and source viewer windows."""
import re

_JS_FORMAT_RE = re.compile(
    r'(?P<lit>"(?:\\.|[^"\\\r\n])*"|\'(?:\\.|[^\'\\\r\n])*\''
    r'|`(?:\\.|[^`\\])*`|//[^\r\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<open>\{)|(?P<close>\})|(?P<semi>;)')


def is_minified_js(text):
    """Return True if JS text has very long minified lines."""
    if not text or len(text) < 500:
        return False
    lines = text.splitlines()
    if not lines:
        return False
    if len(text) // max(len(lines), 1) > 250:
        return True
    return any(len(line) > 1000 for line in lines[:50])


def beautify_minified_js(text):
    """Fast token-aware JS formatter that splits minified code onto lines."""
    indent = 0
    out = []
    pos = 0
    for match in _JS_FORMAT_RE.finditer(text):
        start, end = match.span()
        if start > pos:
            out.append(text[pos:start])
        if match.group('lit'):
            out.append(match.group(0))
        elif match.group('open'):
            indent = min(indent + 1, 16)
            out.append('{\n' + ('  ' * indent))
        elif match.group('close'):
            indent = max(indent - 1, 0)
            out.append('\n' + ('  ' * indent) + '}')
        elif match.group('semi'):
            out.append(';\n' + ('  ' * indent))
        pos = end
    if pos < len(text):
        out.append(text[pos:])
    return ''.join(out)


def format_long_object_line(line):
    """Expand multi-property single-line Hermes object literals across lines."""
    if len(line) <= 300 or '= {' not in line or not line.endswith('};'):
        return [line]
    head, _, rest = line.partition('= {')
    body = rest[:-2]
    indent = len(line) - len(line.lstrip())
    pad = ' ' * (indent + 4)
    end_pad = ' ' * indent
    parts = [p.strip() for p in body.split(', ') if p.strip()]
    if len(parts) < 3:
        return [line]
    expanded = [f'{head}= {{']
    for idx, prop in enumerate(parts):
        suffix = ',' if idx + 1 < len(parts) else ''
        expanded.append(f'{pad}{prop}{suffix}')
    expanded.append(f'{end_pad}}};')
    return expanded


def slice_large_source(text, lines_param, max_bytes=1500000, radius=300):
    """Return (sliced_text, start_line) when a string is too large for DOM."""
    if not text or len(text) <= max_bytes:
        return text, 1
    all_lines = text.splitlines()
    total = len(all_lines)
    target = 1
    if lines_param:
        for tok in str(lines_param).split(','):
            tok = tok.strip()
            if tok.isdigit():
                target = max(1, min(int(tok), total))
                break
    start = max(1, target - radius)
    end = min(total, start + (radius * 2))
    return '\n'.join(all_lines[start - 1:end]), start


def read_js_source_window(file_path, lines_param=None, line_start=None,
                          search_term=None, max_bytes=1500000,
                          window_lines=2000):
    """Read a JS file or a paged window with O(1) RAM and total line count."""
    size = file_path.stat().st_size
    if size <= max_bytes:
        text = file_path.read_text('utf-8', 'ignore')
        total = text.count('\n') + 1
        return {
            'data': text,
            'start_line': 1,
            'end_line': total,
            'total_lines': total,
            'window_lines': window_lines,
            'is_paged': False,
        }

    target_start = None
    if line_start and str(line_start).strip().isdigit():
        target_start = max(1, int(str(line_start).strip()))
    elif lines_param:
        for tok in str(lines_param).split(','):
            tok = tok.strip()
            if tok.isdigit():
                target_start = max(1, int(tok) - (window_lines // 4))
                break

    q_low = search_term.strip().lower() if search_term else ''
    total = 0
    first_match_line = None
    with open(file_path, 'rb') as fbin:
        for idx, raw_bytes in enumerate(fbin, 1):
            total = idx
            if q_low and first_match_line is None:
                if q_low in raw_bytes.decode('utf-8', 'ignore').lower():
                    first_match_line = idx

    if target_start is None:
        if first_match_line is not None:
            target_start = max(1, first_match_line - 100)
        else:
            target_start = 1

    start = min(target_start, max(1, total - window_lines + 1))
    end = min(total, start + window_lines - 1)
    collected = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fp:
        for lno, raw_line in enumerate(fp, 1):
            if lno < start:
                continue
            if lno > end:
                break
            collected.append(raw_line.rstrip('\r\n'))
    return {
        'data': '\n'.join(collected),
        'start_line': start,
        'end_line': end,
        'total_lines': total,
        'window_lines': window_lines,
        'is_paged': True,
    }
