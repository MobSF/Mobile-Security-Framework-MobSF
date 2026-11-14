# -*- coding: utf_8 -*-
"""Minified JavaScript formatting and source viewer windows."""
import re

_JS_TOKEN_RE = re.compile(
    r'(?P<lit>"(?:\\.|[^"\\\r\n])*"|\'(?:\\.|[^\'\\\r\n])*\''
    r'|`(?:\\.|[^`\\])*`|//[^\r\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<slash>/)'
    r'|(?P<open>\{)|(?P<close>\})|(?P<semi>;)')
_REGEX_PRECEDING_KW_RE = re.compile(
    r'(?:^|[^\w$.])(?:return|typeof|instanceof|in|of|void|delete|throw|'
    r'new|case|yield|await)$')
_REGEX_PRECEDING_PUNCT = frozenset('([{:;,=!?&|+-*~^%<>')
_MAX_SINGLE_LINE_CHARS = 8192


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


def _can_start_regex(text, slash_pos):
    """Return True when `/` at slash_pos can start a JS regex literal."""
    idx = slash_pos - 1
    while idx >= 0 and text[idx] in ' \t\r\n':
        idx -= 1
    if idx < 0:
        return True
    ch = text[idx]
    if ch in _REGEX_PRECEDING_PUNCT:
        return True
    window = text[max(0, idx - 15):idx + 1]
    return bool(_REGEX_PRECEDING_KW_RE.search(window))


def _scan_regex_literal_end(text, slash_pos):
    """Return end index past `/pattern/flags`, or None if not a regex."""
    n = len(text)
    idx = slash_pos + 1
    if idx >= n or text[idx] in ('/', '*', '\r', '\n'):
        return None
    in_class = False
    while idx < n:
        ch = text[idx]
        if ch in ('\r', '\n'):
            return None
        if ch == '\\':
            idx += 2
            continue
        if ch == '[':
            in_class = True
        elif ch == ']' and in_class:
            in_class = False
        elif ch == '/' and not in_class:
            idx += 1
            while idx < n and text[idx].isalpha():
                idx += 1
            return idx
        idx += 1
    return None


def beautify_minified_js(text):
    """Fast token-aware JS formatter that splits minified code onto lines."""
    indent = 0
    out = []
    pos = 0
    length = len(text)
    while pos < length:
        match = _JS_TOKEN_RE.search(text, pos)
        if not match:
            out.append(text[pos:])
            break
        start, end = match.span()
        if start > pos:
            out.append(text[pos:start])
        if match.group('lit'):
            out.append(match.group(0))
            pos = end
        elif match.group('slash'):
            regex_end = (
                _scan_regex_literal_end(text, start)
                if _can_start_regex(text, start) else None
            )
            if regex_end is not None:
                out.append(text[start:regex_end])
                pos = regex_end
            else:
                out.append('/')
                pos = end
        elif match.group('open'):
            indent = min(indent + 1, 16)
            out.append('{\n' + ('  ' * indent))
            pos = end
        elif match.group('close'):
            indent = max(indent - 1, 0)
            out.append('\n' + ('  ' * indent) + '}')
            pos = end
        elif match.group('semi'):
            out.append(';\n' + ('  ' * indent))
            pos = end
    return ''.join(out)


def _split_top_level_commas(body):
    """Split an object body on top-level commas outside quotes and brackets."""
    parts = []
    cur = []
    quote = None
    escaped = False
    depth = 0
    for ch in body:
        if quote is not None:
            cur.append(ch)
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', '\'', '`'):
            quote = ch
            cur.append(ch)
        elif ch in '([{':
            depth += 1
            cur.append(ch)
        elif ch in ')]}':
            if depth == 0:
                return None
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            prop = ''.join(cur).strip()
            if prop:
                parts.append(prop)
            cur = []
        else:
            cur.append(ch)
    if quote is not None or depth != 0:
        return None
    tail = ''.join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def format_long_object_line(line):
    """Expand multi-property single-line Hermes object literals across lines."""
    if len(line) <= 300 or '= {' not in line or not line.endswith('};'):
        return [line]
    head, _, rest = line.partition('= {')
    body = rest[:-2]
    parts = _split_top_level_commas(body)
    if not parts or len(parts) < 3:
        return [line]
    indent = len(line) - len(line.lstrip())
    pad = ' ' * (indent + 4)
    end_pad = ' ' * indent
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


def _read_bounded_line(fp, max_chars):
    """Read one logical line, truncating if it exceeds max_chars."""
    chunks = []
    read_chars = 0
    truncated = False
    while True:
        piece = fp.readline(min(65536, max_chars - read_chars + 1))
        if not piece:
            break
        has_nl = piece.endswith(('\n', '\r'))
        if read_chars + len(piece) > max_chars and not has_nl:
            keep = max(0, max_chars - read_chars)
            if keep:
                chunks.append(piece[:keep])
            truncated = True
            # Drain remainder of this oversized physical line in chunks.
            while True:
                rest = fp.readline(65536)
                if not rest or rest.endswith('\n'):
                    break
            break
        chunks.append(piece)
        read_chars += len(piece)
        if has_nl:
            break
    if not chunks and not truncated:
        return None
    text = ''.join(chunks).rstrip('\r\n')
    if truncated:
        text += ' /* ... [line truncated for viewer] ... */'
    return text


def read_js_source_window(file_path, lines_param=None, line_start=None,
                          search_term=None, max_bytes=1500000,
                          window_lines=2000):
    """Read a JS file or a paged window with bounded RAM and total line count."""
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
    has_trailing_partial = False
    line_no = 1
    tail = b''
    needle_bytes = q_low.encode('utf-8')
    overlap = max(0, len(needle_bytes) - 1)
    with open(file_path, 'rb') as fbin:
        while True:
            chunk = fbin.read(1024 * 1024)
            if not chunk:
                break
            has_trailing_partial = not chunk.endswith(b'\n')
            if q_low and first_match_line is None:
                buf = tail + chunk
                idx = buf.lower().find(needle_bytes)
                if idx != -1:
                    before = max(0, idx - len(tail))
                    first_match_line = line_no + chunk[:before].count(b'\n')
                tail = buf[-overlap:] if overlap else b''
            line_no += chunk.count(b'\n')
    total = line_no if has_trailing_partial else max(1, line_no - 1)

    if target_start is None:
        if first_match_line is not None:
            target_start = max(1, first_match_line - 100)
        else:
            target_start = 1

    start = min(target_start, max(1, total - window_lines + 1))
    end = min(total, start + window_lines - 1)
    collected = []
    used_chars = 0
    line_cap = min(_MAX_SINGLE_LINE_CHARS, max_bytes)
    actual_end = start
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fp:
        lno = 0
        while lno < end:
            lno += 1
            if lno < start:
                while True:
                    skipped = fp.readline(65536)
                    if not skipped or skipped.endswith('\n'):
                        break
                if not skipped:
                    break
                continue
            bounded = _read_bounded_line(fp, line_cap)
            if bounded is None:
                break
            if collected and used_chars + len(bounded) > max_bytes:
                break
            collected.append(bounded)
            used_chars += len(bounded) + 1
            actual_end = lno
    return {
        'data': '\n'.join(collected),
        'start_line': start,
        'end_line': actual_end,
        'total_lines': total,
        'window_lines': window_lines,
        'is_paged': True,
    }
