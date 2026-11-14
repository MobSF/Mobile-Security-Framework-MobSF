# -*- coding: utf_8 -*-
"""Hermes bytecode detection, decompilation and normalization."""
import logging
import re
import struct
import subprocess
import sys

from django.conf import settings

from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import append_scan_status
from mobsf.StaticAnalyzer.views.common.js_analysis.constants import (
    HERMES_MAGIC,
    MAX_URL_SCAN_BYTES,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.viewer import (
    format_long_object_line,
)


logger = logging.getLogger(__name__)
_REG_ASSIGN_RE = re.compile(r'^(\s*)(r\d+)\s*=\s*(.+);$')
_REG_SUBSCRIPT_ASSIGN_RE = re.compile(
    r'^(\s*)(r\d+\[[\'"][^\'"]+[\'"]\])\s*=\s*(r\d+);$')
_REG_BIND_CALL_RE = re.compile(r'^(r\d+)\.bind\((r\d+)\)\((.*)\)$')
_OBJ_CREATE_CTOR_RE = re.compile(
    r'^Object\.create\(r\d+(?:\.prototype'
    r'|,\s*\{constructor:\s*\{value:\s*(r\d+)\}\})\)$')
_REG_TOKEN_RE = re.compile(r'\br\d+\b')
_SAFE_EXPR_RE = re.compile(
    r'^(?:true|false|null|-?\d+(?:\.\d+)?|[\'"][^\r\n]{0,80}[\'"]'
    r'|r\d+(?:\.[A-Za-z_$][\w$]*)+)$')


def is_hermes_bytecode(file_path):
    """Return (is_hermes, bytecode_version) for a candidate file."""
    try:
        with open(file_path, 'rb') as fp:
            header = fp.read(12)
        if len(header) >= 12 and header[:8] == HERMES_MAGIC:
            version = struct.unpack('<I', header[8:12])[0]
            return True, int(version)
    except OSError:
        pass
    return False, None


def _fold_args(args_str, reg_map):
    """Replace register tokens inside a call argument list."""
    if not args_str.strip():
        return args_str

    def _repl(match):
        tok = match.group(0)
        return reg_map.get(tok, tok)

    return _REG_TOKEN_RE.sub(_repl, args_str)


def _rewrite_hermes_rhs(lhs, rhs, reg_map, ctor_map):
    """Fold register assignments and .bind() calls in hermes-dec output."""
    ctor_match = _OBJ_CREATE_CTOR_RE.match(rhs)
    if ctor_match:
        ctor_reg = ctor_match.group(1)
        if ctor_reg:
            ctor_map[lhs] = reg_map.get(ctor_reg, ctor_reg)
        return rhs

    bind_match = _REG_BIND_CALL_RE.match(rhs)
    if bind_match:
        fn_reg, this_reg, raw_args = bind_match.groups()
        folded_args = _fold_args(raw_args, reg_map)
        if this_reg in ctor_map:
            return f'new {ctor_map[this_reg]}({folded_args})'
        fn_expr = reg_map.get(fn_reg, fn_reg)
        return f'{fn_expr}({folded_args})'

    if rhs in reg_map:
        return reg_map[rhs]

    if '.' in rhs and rhs.startswith('r'):
        base_reg, _, tail = rhs.partition('.')
        if base_reg in reg_map and not reg_map[base_reg].startswith(("'", '"')):
            return f'{reg_map[base_reg]}.{tail}'
    return rhs


def _normalize_hermes_stream(raw_path, dec_path):
    """Stream-normalize hermes-dec output with O(1) memory usage."""
    reg_map = {}
    ctor_map = {}
    in_disassembly = False

    with open(raw_path, 'r', encoding='utf-8', errors='ignore') as src, open(
            dec_path, 'w', encoding='utf-8') as dst:
        for raw_line in src:
            line = raw_line.rstrip('\r\n')
            stripped = line.strip()
            if stripped.startswith('==== Falling back to Disassembly ===='):
                in_disassembly = True
                dst.write(f'// {line}\n')
                continue
            if in_disassembly:
                if line.startswith(('function', '}')):
                    in_disassembly = False
                else:
                    dst.write(f'// {line}\n')
                    continue

            if stripped.startswith(('function', 'case ', '{', '}')):
                reg_map.clear()
                ctor_map.clear()

            sub_match = _REG_SUBSCRIPT_ASSIGN_RE.match(line)
            if sub_match:
                indent, target, val_reg = sub_match.groups()
                resolved = reg_map.get(val_reg, val_reg)
                dst.write(f'{indent}{target} = {resolved};\n')
                continue

            assign_match = _REG_ASSIGN_RE.match(line)
            if assign_match:
                indent, lhs, rhs = assign_match.groups()
                new_rhs = _rewrite_hermes_rhs(lhs, rhs, reg_map, ctor_map)
                if (_SAFE_EXPR_RE.match(new_rhs)
                        and len(new_rhs) <= 96
                        and lhs not in new_rhs):
                    reg_map[lhs] = new_rhs
                else:
                    reg_map.pop(lhs, None)
                for exp_line in format_long_object_line(
                        f'{indent}{lhs} = {new_rhs};'):
                    dst.write(f'{exp_line}\n')
                continue

            for exp_line in format_long_object_line(line):
                dst.write(f'{exp_line}\n')


def extract_hermes_strings(bundle_path):
    """Extract string table from a Hermes bytecode file via HBCReader."""
    try:
        from hermes_dec.parsers.hbc_file_parser import HBCReader
        with open(bundle_path, 'rb') as fp:
            reader = HBCReader()
            reader.read_whole_file(fp)
            return [s for s in (reader.strings or []) if isinstance(s, str)]
    except Exception:
        try:
            raw = bundle_path.read_bytes()[:MAX_URL_SCAN_BYTES]
            return [
                m.group(0).decode('utf-8', 'ignore')
                for m in re.finditer(rb'[\x20-\x7e]{6,200}', raw)
            ]
        except OSError:
            return []


def decompile_hermes_bundle(checksum, bundle_path, scan_root):
    """Decompile a Hermes bytecode file to <name>.dec.js using hermes-dec."""
    dec_path = bundle_path.with_name(f'{bundle_path.name}.dec.js')
    raw_tmp = bundle_path.with_name(f'{bundle_path.name}.raw.dec.js')
    try:
        rel = dec_path.relative_to(scan_root).as_posix()
        if (not is_safe_path(scan_root, dec_path, rel)
                or is_pipe_or_link(bundle_path)):
            return None
        msg = f'Decompiling Hermes bytecode bundle: {bundle_path.name}'
        logger.info(msg)
        append_scan_status(checksum, msg)
        timeout = getattr(settings, 'SAST_TIMEOUT', 1800)
        subprocess.run(
            [
                sys.executable,
                '-m',
                'hermes_dec.decompilation.hbc_decompiler',
                bundle_path.as_posix(),
                raw_tmp.as_posix(),
            ],
            timeout=timeout,
            capture_output=True,
            check=False,
        )
        if raw_tmp.is_file() and raw_tmp.stat().st_size > 0:
            _normalize_hermes_stream(raw_tmp, dec_path)
            raw_tmp.unlink()
            return dec_path
    except Exception as exp:
        logger.warning(
            'Hermes decompilation failed for %s: %s',
            sanitize_for_logging(bundle_path.name),
            sanitize_for_logging(repr(exp)),
        )
    finally:
        if raw_tmp.exists() and not is_pipe_or_link(raw_tmp):
            try:
                raw_tmp.unlink()
            except OSError:
                pass
    if dec_path.exists() and not is_pipe_or_link(dec_path):
        try:
            dec_path.unlink()
        except OSError:
            pass
    return None
