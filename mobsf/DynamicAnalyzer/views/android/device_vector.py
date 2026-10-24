"""Convert bounded Android vector drawables to safe SVG images."""
import math
import re
from xml.etree import ElementTree as XmlElementTree

from defusedxml import ElementTree

from mobsf.MobSF.security import sanitize_svg
from mobsf.StaticAnalyzer.tools.androguard4.apk import NS_ANDROID
from mobsf.StaticAnalyzer.tools.androguard4.axml import AXMLPrinter

_MAX_IMAGE = 1_500_000
_MAX_PATHS = 256
_MAX_PATH_DATA = 200_000
_SVG_NS = 'http://www.w3.org/2000/svg'


def _number(value, default=None):
    """Return one bounded finite Android vector number."""
    if not isinstance(value, str):
        return default
    match = re.fullmatch(
        r'\s*(-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)'
        r'(?:dip|dp|sp|px)?\s*',
        value,
    )
    if not match:
        return default
    number = float(match.group(1))
    if not math.isfinite(number) or abs(number) > 1_000_000:
        return default
    return number


def _color(value):
    """Convert one literal Android color to SVG color and opacity."""
    if not isinstance(value, str):
        return None, None
    color = value.strip()
    if not re.fullmatch(r'#[A-Fa-f0-9]{3,8}', color):
        return None, None
    digits = color[1:]
    if len(digits) == 3:
        return f'#{digits}', 1.0
    if len(digits) == 4:
        alpha = int(digits[0] * 2, 16) / 255
        return f'#{digits[1:]}', alpha
    if len(digits) == 6:
        return f'#{digits}', 1.0
    if len(digits) == 8:
        alpha = int(digits[:2], 16) / 255
        return f'#{digits[2:]}', alpha
    return None, None


def _transform(element):
    """Translate an Android vector group transform to SVG."""
    values = {
        name: _number(
            element.get(NS_ANDROID + name) or element.get(name),
            default,
        )
        for name, default in (
            ('rotation', 0.0),
            ('pivotX', 0.0),
            ('pivotY', 0.0),
            ('scaleX', 1.0),
            ('scaleY', 1.0),
            ('translateX', 0.0),
            ('translateY', 0.0),
        )
    }
    transforms = []
    if values['translateX'] or values['translateY']:
        transforms.append(
            f'translate({values["translateX"]:g} '
            f'{values["translateY"]:g})')
    if values['rotation']:
        transforms.append(
            f'rotate({values["rotation"]:g} '
            f'{values["pivotX"]:g} {values["pivotY"]:g})')
    if values['scaleX'] != 1 or values['scaleY'] != 1:
        pivot_x = values['pivotX']
        pivot_y = values['pivotY']
        if pivot_x or pivot_y:
            transforms.append(f'translate({pivot_x:g} {pivot_y:g})')
        transforms.append(
            f'scale({values["scaleX"]:g} {values["scaleY"]:g})')
        if pivot_x or pivot_y:
            transforms.append(f'translate({-pivot_x:g} {-pivot_y:g})')
    return ' '.join(transforms)


def safe_svg_image(data):
    """Return sanitized SVG bytes suitable for an image response."""
    if not data or len(data) > _MAX_IMAGE:
        return None
    try:
        cleaned = sanitize_svg(
            data.decode('utf-8', 'strict')).encode('utf-8')
    except ValueError:
        return None
    if (len(cleaned) > _MAX_IMAGE
            or not cleaned.lstrip().startswith(b'<svg')):
        return None
    try:
        root = ElementTree.fromstring(cleaned)
    except Exception:
        return None
    allowed = {
        'svg': {'width', 'height', 'viewBox', 'version'},
        'g': {'transform'},
        'path': {'d', 'fill', 'stroke', 'stroke-width', 'opacity'},
    }
    path_bytes = 0
    for element in root.iter():
        tag = (
            element.tag.split('}')[-1]
            if isinstance(element.tag, str) else ''
        )
        if tag not in allowed:
            return None
        attributes = {
            name.split('}')[-1]
            for name in element.attrib
        }
        if not attributes.issubset(allowed[tag]):
            return None
        if tag == 'path':
            path_data = element.get('d', '')
            path_bytes += len(path_data)
            if (path_bytes > _MAX_PATH_DATA
                    or not re.fullmatch(
                        r'[A-Za-z0-9eE.,+\-\s]+', path_data)):
                return None
    return cleaned, 'image/svg+xml'


def vector_image(xml_bytes):
    """Convert a bounded Android vector drawable to sanitized SVG."""
    try:
        root = AXMLPrinter(xml_bytes).get_xml_obj()
    except Exception:
        return None
    if (root is None
            or not isinstance(root.tag, str)
            or root.tag.split('}')[-1] != 'vector'):
        return None
    viewport_width = _number(
        root.get(NS_ANDROID + 'viewportWidth')
        or root.get('viewportWidth'))
    viewport_height = _number(
        root.get(NS_ANDROID + 'viewportHeight')
        or root.get('viewportHeight'))
    if (not viewport_width
            or not viewport_height
            or viewport_width <= 0
            or viewport_height <= 0):
        return None
    svg = XmlElementTree.Element('svg', {
        'xmlns': _SVG_NS,
        'version': '1.1',
        'width': '128',
        'height': '128',
        'viewBox': f'0 0 {viewport_width:g} {viewport_height:g}',
    })
    path_count = 0
    path_bytes = 0

    def add_children(android_parent, svg_parent):
        nonlocal path_count, path_bytes
        for child in android_parent:
            tag = (
                child.tag.split('}')[-1]
                if isinstance(child.tag, str) else ''
            )
            if tag == 'group':
                group = XmlElementTree.SubElement(svg_parent, 'g')
                transform = _transform(child)
                if transform:
                    group.set('transform', transform)
                add_children(child, group)
                continue
            if tag != 'path' or path_count >= _MAX_PATHS:
                continue
            path_data = (
                child.get(NS_ANDROID + 'pathData')
                or child.get('pathData')
            )
            if (not isinstance(path_data, str)
                    or not path_data
                    or not re.fullmatch(
                        r'[A-Za-z0-9eE.,+\-\s]+', path_data)):
                continue
            path_bytes += len(path_data)
            if path_bytes > _MAX_PATH_DATA:
                return
            attributes = {'d': path_data}
            fill, fill_opacity = _color(
                child.get(NS_ANDROID + 'fillColor')
                or child.get('fillColor'))
            if fill:
                attributes['fill'] = fill
                explicit = _number(
                    child.get(NS_ANDROID + 'fillAlpha')
                    or child.get('fillAlpha'), 1.0)
                attributes['opacity'] = (
                    f'{max(0.0, min(1.0, fill_opacity * explicit)):g}')
            else:
                attributes['fill'] = 'none'
            stroke, stroke_opacity = _color(
                child.get(NS_ANDROID + 'strokeColor')
                or child.get('strokeColor'))
            if stroke:
                attributes['stroke'] = stroke
                width = _number(
                    child.get(NS_ANDROID + 'strokeWidth')
                    or child.get('strokeWidth'), 1.0)
                attributes['stroke-width'] = f'{max(0.0, width):g}'
                if not fill:
                    explicit = _number(
                        child.get(NS_ANDROID + 'strokeAlpha')
                        or child.get('strokeAlpha'), 1.0)
                    attributes['opacity'] = (
                        f'{max(0.0, min(1.0, stroke_opacity * explicit)):g}')
            XmlElementTree.SubElement(svg_parent, 'path', attributes)
            path_count += 1

    add_children(root, svg)
    if not path_count or path_bytes > _MAX_PATH_DATA:
        return None
    rendered = XmlElementTree.tostring(svg, encoding='utf-8')
    return safe_svg_image(rendered)
