import os

from django.conf import settings

from mobsf.MobSF.utils import strict_package_check


def get_content(file_name):
    content = ''
    script = os.path.join(settings.TOOLS_DIR,
                          'frida_scripts',
                          'auxiliary',
                          file_name)

    with open(script, 'r',
              encoding='utf8',
              errors='ignore') as scp:
        content = scp.read()
    return content


def get_loaded_classes():
    """Get Loaded classes."""
    return get_content('get_loaded_classes.js')


def string_catch():
    """Capture all runtime strings."""
    return get_content('string_catch.js')


def string_compare():
    """Capture all runtime string comparisons."""
    return get_content('string_compare.js')


def get_methods(klazz):
    """Get Class methods and implementations."""
    if not strict_package_check(klazz):
        return ''
    content = get_content('get_methods.js')
    return content.replace('{{CLASS}}', klazz)


def class_pattern(pattern):
    """Search in loaded classes based on pattern."""
    pattern = pattern.replace(
        '/', '\\/').replace(';', '')
    content = get_content('search_class_pattern.js')
    return content.replace('{{PATTERN}}', pattern)


def class_trace(classes):
    """Trace all methods of a class."""
    filtered = []
    if ',' not in classes:
        filtered.append(classes.strip())
    else:
        for clz in classes.split(','):
            filtered.append(clz.strip())
    for klz in filtered:
        if not strict_package_check(klz):
            return ''
    content = get_content('class_trace.js')
    return content.replace('{{CLASSES}}', str(filtered))
