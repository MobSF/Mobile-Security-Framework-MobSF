from pathlib import Path

from django.conf import settings

from mobsf.MobSF.utils import (
    strict_ios_class,
)


def get_content(file_name):
    tools_dir = Path(settings.TOOLS_DIR)
    aux_dir = tools_dir / 'frida_scripts' / 'ios' / 'auxiliary'
    script = aux_dir / file_name

    if script.exists():
        return script.read_text('utf-8', 'ignore')
    return ''


def get_loaded_classes():
    """Get Loaded classes."""
    return get_content('find-app-classes.js')


def get_loaded_classes_methods():
    """Get Loaded classes and methods."""
    return get_content('find-app-classes-methods.js')


def string_capture():
    """Capture all runtime strings."""
    return get_content('string-capture.js')


def string_compare():
    """Capture all runtime string comparisons."""
    return get_content('string-compare.js')


def get_methods(klazz):
    """Get Class methods and implementations."""
    if not strict_ios_class(klazz):
        return ''
    content = get_content('get-methods.js')
    return content.replace('{{CLASS}}', klazz)


def classes_with_method(method):
    """Get all classes containing the method."""
    if not strict_ios_class(method):
        return ''
    content = get_content('find-specific-method.js')
    return content.replace('{{METHOD}}', method)


def class_pattern(pattern):
    """Search in loaded classes based on pattern."""
    pattern = pattern.replace(
        '/', '\\/').replace(';', '')
    content = get_content('search-class-pattern.js')
    return content.replace('{{PATTERN}}', pattern)


def class_trace(class_name):
    """Trace all methods of a class."""
    if not strict_ios_class(class_name):
        return ''
    content = get_content('class-trace.js')
    return content.replace('{{CLASS}}', class_name)
