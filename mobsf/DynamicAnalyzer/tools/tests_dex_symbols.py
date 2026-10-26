"""Parser checks for Gadget dex symbol lookup.

These build tiny in-memory dex buffers and call
``GadgetPatcher._parse_dex_symbols``. They do not write an APK.
"""
import struct
import time
import tracemalloc

from django.test import SimpleTestCase

from mobsf.DynamicAnalyzer.tools.apk_patcher import GadgetPatcher

_GET_PROCESS_NAME = (
    'Landroid/app/Application;', 'getProcessName', '()Ljava/lang/String;')
_CURRENT_PROCESS_NAME = (
    'Landroid/app/ActivityThread;',
    'currentProcessName',
    '()Ljava/lang/String;',
)
_STRING_EQUALS = (
    'Ljava/lang/String;', 'equals', '(Ljava/lang/Object;)Z')
_LOAD_LIBRARY = (
    'Ljava/lang/System;', 'loadLibrary', '(Ljava/lang/String;)V')
_SDK_INT_FIELD = ('Landroid/os/Build$VERSION;', 'SDK_INT', 'I')
# 128 UTF-16 units is the production cap. The read window is 3 bytes
# per unit plus the NUL, and must not grow past that.
_MAX_WINDOW = 128 * 3 + 1


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _mutf(text):
    raw = text.encode('utf-8')
    return _uleb(len(text)) + raw + b'\x00'


def _literal(utf16_size, body, terminated=True):
    blob = _uleb(utf16_size) + body
    if terminated:
        blob += b'\x00'
    return blob


class _BoundedView(bytes):
    """Record string reads and refuse a window above the symbol cap."""

    def __new__(cls, source):
        view = bytes.__new__(cls, source)
        view.searches = 0
        view.max_window = 0
        return view

    def find(self, sub, start=0, end=None):
        if start is None:
            start = 0
        if end is None:
            end = len(self)
        window = end - start
        self.searches += 1
        if window > self.max_window:
            self.max_window = window
        if window > _MAX_WINDOW:
            raise AssertionError(
                f'dex string search window is {window} bytes')
        return super().find(sub, start, end)

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = 0 if item.start is None else item.start
            stop = len(self) if item.stop is None else item.stop
            if stop - start > _MAX_WINDOW:
                raise AssertionError(
                    f'dex string slice is {stop - start} bytes')
        return bytes.__getitem__(self, item)


def _build_dex(strings, types, protos, methods, fields, repeat_last=0):
    """Assemble the dex sections this parser actually reads."""
    string_count = len(strings) + repeat_last
    string_ids_off = 112
    type_ids_off = string_ids_off + (4 * string_count)
    proto_ids_off = type_ids_off + (4 * len(types))
    field_ids_off = proto_ids_off + (12 * len(protos))
    method_ids_off = field_ids_off + (8 * len(fields))
    data_off = method_ids_off + (8 * len(methods))

    type_lists = []
    params_off = []
    cursor = data_off
    for _return_type, params in protos:
        if not params:
            params_off.append(0)
            continue
        blob = struct.pack('<I', len(params))
        for param in params:
            blob += struct.pack('<H', param)
        params_off.append(cursor)
        type_lists.append(blob)
        cursor += len(blob)

    string_offs = []
    for item in strings:
        string_offs.append(cursor)
        cursor += len(item)

    header = bytearray(112)
    header[0:8] = b'dex\n035\x00'
    struct.pack_into('<I', header, 32, cursor)
    struct.pack_into('<I', header, 36, 112)
    struct.pack_into('<I', header, 56, string_count)
    struct.pack_into('<I', header, 60, string_ids_off)
    struct.pack_into('<I', header, 64, len(types))
    struct.pack_into('<I', header, 68, type_ids_off)
    struct.pack_into('<I', header, 72, len(protos))
    struct.pack_into('<I', header, 76, proto_ids_off)
    struct.pack_into('<I', header, 80, len(fields))
    struct.pack_into('<I', header, 84, field_ids_off)
    struct.pack_into('<I', header, 88, len(methods))
    struct.pack_into('<I', header, 92, method_ids_off)

    parts = [bytes(header)]
    for offset in string_offs:
        parts.append(struct.pack('<I', offset))
    if string_offs and repeat_last:
        shared = struct.pack('<I', string_offs[-1])
        parts.append(shared * repeat_last)
    for type_index in types:
        parts.append(struct.pack('<I', type_index))
    for (return_type, _params), param_at in zip(protos, params_off):
        parts.append(struct.pack('<III', 0, return_type, param_at))
    for class_index, type_index, name_index in fields:
        parts.append(struct.pack('<HHI', class_index, type_index, name_index))
    for class_index, proto_index, name_index in methods:
        parts.append(struct.pack('<HHI', class_index, proto_index, name_index))
    parts.extend(type_lists)
    parts.extend(strings)
    blob = b''.join(parts)
    if len(blob) != cursor:
        raise RuntimeError('dex builder size mismatch')
    return blob


def _symbol_dex(extra_strings=(), extra_methods=(), repeat_last=0):
    strings = [
        _mutf('Landroid/app/Application;'),
        _mutf('getProcessName'),
        _mutf('Ljava/lang/String;'),
        _mutf('Landroid/app/ActivityThread;'),
        _mutf('currentProcessName'),
        _mutf('Ljava/lang/System;'),
        _mutf('loadLibrary'),
        _mutf('Ljava/lang/Object;'),
        _mutf('equals'),
        _mutf('V'),
        _mutf('Z'),
        _mutf('Landroid/os/Build$VERSION;'),
        _mutf('SDK_INT'),
        _mutf('I'),
        *extra_strings,
    ]
    types = [0, 2, 3, 5, 7, 9, 10, 11, 13]
    protos = [
        (1, []),
        (5, [1]),
        (6, [4]),
    ]
    methods = [
        (0, 0, 1),
        (2, 0, 4),
        (3, 1, 6),
        (1, 2, 8),
        *extra_methods,
    ]
    fields = [(7, 8, 12)]
    return _build_dex(
        strings, types, protos, methods, fields, repeat_last=repeat_last)


def _longest(methods, fields):
    longest = 0
    for pool in (methods, fields):
        for ref in pool:
            for part in ref:
                longest = max(longest, len(part))
    return longest


class DexSymbolParserTests(SimpleTestCase):
    """Short loader symbols stay visible; long literals are not copied."""

    def test_symbols_survive_long_literals(self):
        name_128 = 'B' * 128
        name_129 = 'C' * 129
        name_5000 = 'A' * 5000
        base = 14
        blob = _symbol_dex(
            extra_strings=(
                _mutf(name_128),
                _mutf(name_129),
                _mutf(name_5000),
            ),
            extra_methods=(
                (0, 0, base),
                (0, 0, base + 1),
                (0, 0, base + 2),
            ),
        )
        view = _BoundedView(blob)
        started = time.perf_counter()
        methods, fields, counts = GadgetPatcher._parse_dex_symbols(view)
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 1.0)
        self.assertLessEqual(view.max_window, _MAX_WINDOW)
        self.assertLess(view.searches, 64)
        self.assertEqual(counts, {'methods': 7, 'fields': 1})
        self.assertIn(_GET_PROCESS_NAME, methods)
        self.assertIn(_CURRENT_PROCESS_NAME, methods)
        self.assertIn(_STRING_EQUALS, methods)
        self.assertIn(_LOAD_LIBRARY, methods)
        self.assertIn(_SDK_INT_FIELD, fields)
        self.assertIn(
            ('Landroid/app/Application;', name_128, '()Ljava/lang/String;'),
            methods,
        )
        self.assertNotIn(name_129, {part for ref in methods for part in ref})
        self.assertNotIn(name_5000, {part for ref in methods for part in ref})
        self.assertLessEqual(_longest(methods, fields), 128)
        self.assertEqual(len(methods), 5)

    def test_huge_uleb_is_not_a_read_window(self):
        huge = _literal(2 ** 28, b'\xff' * 64, terminated=False)
        blob = _symbol_dex(
            extra_strings=(huge,),
            extra_methods=((0, 0, 14),),
        )
        view = _BoundedView(blob)
        started = time.perf_counter()
        methods, _fields, counts = GadgetPatcher._parse_dex_symbols(view)
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 1.0)
        self.assertLessEqual(view.max_window, _MAX_WINDOW)
        self.assertIn(_GET_PROCESS_NAME, methods)
        self.assertEqual(counts['methods'], 5)
        self.assertEqual(len(methods), 4)
        self.assertLessEqual(_longest(methods, _fields), 128)

    def test_missing_nul_in_window_is_truncated(self):
        # The declared size is 4, so the legal window is 13 bytes.
        # A NUL much later must not be treated as the terminator.
        late = _literal(4, b'Q' * 2000, terminated=True)
        blob = _symbol_dex(
            extra_strings=(late,),
            extra_methods=((0, 0, 14),),
        )
        with self.assertRaises(ValueError) as raised:
            GadgetPatcher._parse_dex_symbols(blob)
        self.assertIn('Truncated', str(raised.exception))

    def test_string_offset_past_eof_is_truncated(self):
        blob = bytearray(_symbol_dex())
        # String id 1 is getProcessName. Point it past the buffer.
        struct.pack_into('<I', blob, 112 + 4, len(blob) + 32)
        with self.assertRaises(ValueError) as raised:
            GadgetPatcher._parse_dex_symbols(bytes(blob))
        self.assertIn('Truncated', str(raised.exception))

    def test_unreferenced_string_ids_are_not_copied(self):
        payload = b'L' * 8192
        blob = _symbol_dex(
            extra_strings=(_literal(len(payload), payload),),
            extra_methods=((0, 0, 14),),
            repeat_last=100_000,
        )
        view = _BoundedView(blob)
        tracemalloc.start()
        started = time.perf_counter()
        methods, fields, counts = GadgetPatcher._parse_dex_symbols(view)
        elapsed = time.perf_counter() - started
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertLess(elapsed, 1.0, f'elapsed {elapsed:.3f}s')
        self.assertLess(peak, 2_000_000, f'peak {peak} bytes')
        self.assertLess(view.searches, 64)
        self.assertGreater(counts['methods'], 4)
        self.assertIn(_LOAD_LIBRARY, methods)
        self.assertIn(_SDK_INT_FIELD, fields)
        self.assertLessEqual(_longest(methods, fields), 128)
        self.assertNotIn(payload.decode(), {
            part for ref in methods for part in ref
        })
