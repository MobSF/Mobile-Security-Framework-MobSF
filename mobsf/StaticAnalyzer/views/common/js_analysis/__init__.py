# -*- coding: utf_8 -*-
"""JavaScript, TypeScript, Hybrid & Hermes Bytecode Static Analysis."""
from mobsf.StaticAnalyzer.views.common.js_analysis.analyzer import (
    analyze_android_js,
    analyze_ios_js,
    analyze_js,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.files import (
    cached_js_source_files,
    list_js_source_files,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.hermes import (
    decompile_hermes_bundle,
    is_hermes_bytecode,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.viewer import (
    beautify_minified_js,
    is_minified_js,
    read_js_source_window,
    slice_large_source,
)

__all__ = [
    'analyze_android_js',
    'analyze_ios_js',
    'analyze_js',
    'beautify_minified_js',
    'cached_js_source_files',
    'decompile_hermes_bundle',
    'is_hermes_bytecode',
    'is_minified_js',
    'list_js_source_files',
    'read_js_source_window',
    'slice_large_source',
]
