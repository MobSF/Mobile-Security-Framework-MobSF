# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import fnmatch
import logging
import math
import os
import re
from pathlib import Path
from shutil import copy2, copytree
from xml.etree import ElementTree as XmlElementTree

from defusedxml import ElementTree as DefusedET
from defusedxml.minidom import parseString

from lxml import etree

from django.conf import settings

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
    sanitize_for_logging,
    sanitize_svg,
)
from mobsf.MobSF.utils import (
    append_scan_status,
)
from mobsf.StaticAnalyzer.tools.androguard4 import (
    axml,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    RESERVED_FILE_NAMES,
)


logger = logging.getLogger(__name__)


KNOWN_MIPMAP_SIZES = [
    '-hdpi',
    '-hdpi-v4',
    '-xhdpi',
    '-xhdpi-v4',
    '-mdpi',
    '-mdpi-v4',
]

PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
ANDROID_SYSTEM_COLORS = (
    (b'@android:0106000D', b'#00000000'),
    (b'@android:0106000d', b'#00000000'),
    (b'@android:color/transparent', b'#00000000'),
    (b'@android:0106000B', b'#FFFFFFFF'),
    (b'@android:0106000b', b'#FFFFFFFF'),
    (b'@android:color/white', b'#FFFFFFFF'),
    (b'@android:0106000C', b'#FF000000'),
    (b'@android:0106000c', b'#FF000000'),
    (b'@android:color/black', b'#FF000000'),
)


def _is_valid_icon_file(file_path):
    """Verify a candidate icon file is non-empty and has valid image magic/content."""
    try:
        path = Path(file_path)
        if (not path.is_file()
                or is_pipe_or_link(path)
                or path.stat().st_size == 0):
            return False
        suffix = path.suffix.lower()
        if suffix in ('.png', '.webp'):
            with path.open('rb') as fp:
                header = fp.read(12)
                return (
                    header[:8] == PNG_MAGIC
                    or (len(header) >= 12
                        and header[:4] == b'RIFF'
                        and header[8:12] == b'WEBP')
                )
        if suffix == '.svg':
            with path.open('rb') as fp:
                head = fp.read(512)
                return b'<svg' in head
        return False
    except OSError:
        return False


def _search_folder(src, file_pattern):
    matches = []
    for root, _, filenames in os.walk(src):
        for filename in fnmatch.filter(filenames, file_pattern):
            matches.append(os.path.join(root, filename))
    return matches


DENSITY_ORDER = (
    'xxxhdpi',
    'xxhdpi',
    'xhdpi',
    'hdpi',
    'mdpi',
)


def _density_rank(path_str):
    """Rank resource paths from highest density (0) to lowest."""
    parent = Path(path_str).parent.name.lower()
    for idx, token in enumerate(DENSITY_ORDER):
        if token in parent:
            return idx
    return len(DENSITY_ORDER)


def _index_res_files(roots):
    """Build a single-pass {filename: [paths]} index across resource roots."""
    index = {}
    for root in roots:
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                index.setdefault(fname, []).append(
                    Path(dirpath, fname).as_posix())
    for paths in index.values():
        paths.sort(key=_density_rank)
    return index


def _is_safe_icon_path(root, icon_file):
    """Verify a resolved icon path remains inside its application root."""
    try:
        if is_pipe_or_link(icon_file):
            return False
        resolved_root = Path(root).resolve()
        resolved_icon = Path(icon_file).resolve()
        relative_icon = resolved_icon.relative_to(resolved_root)
    except (OSError, ValueError):
        return False
    return is_safe_path(resolved_root, resolved_icon, relative_icon)


def _extract_drawable_refs_from_xml(xml_path):
    """Extract drawable/mipmap resource names referenced inside an XML icon."""
    refs = []
    try:
        path = Path(xml_path)
        if not path.is_file() or is_pipe_or_link(path):
            return refs
        parsed = parseString(path.read_text('utf8', 'ignore'))
        for tag in ('foreground', 'monochrome', 'item', 'bitmap', 'background'):
            for node in parsed.getElementsByTagName(tag):
                for attr in ('android:drawable', 'android:src'):
                    val = node.getAttribute(attr)
                    if val and '/' in val:
                        name = val.rsplit('/', 1)[1].strip()
                        if (name
                                and not is_path_traversal(name)
                                and not any(
                                    c in name
                                    for c in ('*', '?', '[', '/', '\\'))
                                and name not in refs):
                            refs.append(name)
    except Exception:
        pass
    return refs


def _is_launcher_component(node, ns='android'):
    """Return True if an activity/alias declares MAIN or LAUNCHER intent."""
    for sitem in node.getElementsByTagName('action'):
        if sitem.getAttribute(f'{ns}:name') == 'android.intent.action.MAIN':
            return True
    for sitem in node.getElementsByTagName('category'):
        val = sitem.getAttribute(f'{ns}:name')
        if val in (
            'android.intent.category.LAUNCHER',
            'android.intent.category.INFO',
        ):
            return True
    return False


def _ordered_manifest_icon_nodes(parsed, ns='android'):
    """Yield enabled application, launcher components, then other components."""
    apps = parsed.getElementsByTagName('application')
    comp_nodes = [
        n for tag in ('activity-alias', 'activity')
        for n in parsed.getElementsByTagName(tag)
        if n.getAttribute(f'{ns}:enabled').strip().lower() != 'false'
    ]
    launchers = [n for n in comp_nodes if _is_launcher_component(n, ns)]
    others = [n for n in comp_nodes if not _is_launcher_component(n, ns)]
    return (*apps, *launchers, *others)


def _extract_manifest_icon_names(app_dir):
    """Extract non-null icon resource names from AndroidManifest.xml."""
    names = []
    for rel in ('apktool_out/AndroidManifest.xml', 'AndroidManifest.xml'):
        mfst = Path(app_dir) / rel
        if not mfst.is_file() or is_pipe_or_link(mfst):
            continue
        try:
            parsed = parseString(mfst.read_text('utf8', 'ignore'))
            for node in _ordered_manifest_icon_nodes(parsed):
                for attr in ('android:icon', 'android:roundIcon'):
                    val = node.getAttribute(attr).strip()
                    if not val or val == '@null' or '/' not in val:
                        continue
                    name = val.rsplit('/', 1)[1].strip()
                    if (name
                            and not is_path_traversal(name)
                            and not any(
                                c in name
                                for c in ('*', '?', '[', '/', '\\'))
                            and name not in names):
                        names.append(name)
        except Exception:
            continue
        if names:
            break
    return names


def guess_icon_path(res_dir):
    res_path = Path(res_dir)
    app_dir = res_path.parent
    apktool_res = app_dir / 'apktool_out' / 'res'
    search_roots = [r for r in (res_path, apktool_res) if r.exists()]

    res_index = _index_res_files(search_roots)
    manifest_icon_names = _extract_manifest_icon_names(app_dir)
    for icon_stem in manifest_icon_names:
        stem_matches = [
            match
            for ext in ('.png', '.webp', '.svg')
            for match in res_index.get(f'{icon_stem}{ext}', ())
        ]
        stem_matches.sort(key=_density_rank)
        for match in stem_matches:
            if _is_valid_icon_file(match):
                return match

    icon_folders = (
        'mipmap-xxxhdpi',
        'mipmap-xxhdpi',
        'mipmap-xhdpi',
        'mipmap-hdpi',
        'mipmap-hdpi-v4',
        'mipmap-mdpi',
        'drawable',
    )
    candidate_names = (
        'ic_launcher.png',
        'ic_launcher.webp',
        'ic_launcher_round.png',
        'ic_launcher_round.webp',
        'ic_launcher_foreground.png',
        'ic_launcher_foreground.webp',
    )
    for root in search_roots:
        for icon_folder in icon_folders:
            for candidate_name in candidate_names:
                guessed = root / icon_folder / candidate_name
                if _is_valid_icon_file(guessed):
                    return guessed.as_posix()

    for fname, paths in res_index.items():
        if (fname.startswith('ic_launcher')
                and not fname.startswith('ic_launcher_background')):
            for candidate in paths:
                if _is_valid_icon_file(candidate):
                    return candidate

    # XAPK bundles often include a rendered top-level icon.png / icon.webp
    for root_icon_name in ('icon.png', 'icon.webp'):
        root_icon = app_dir / root_icon_name
        if (_is_safe_icon_path(app_dir, root_icon)
                and _is_valid_icon_file(root_icon)):
            return root_icon.as_posix()

    # Follow adaptive-icon / layer-list XML references using the indexed map
    xml_candidates = [
        p for fname, paths in res_index.items()
        if (fname.startswith('ic_launcher')
            or fname[:-4] in manifest_icon_names)
        and fname.endswith('.xml')
        for p in paths
    ]
    for xml_file in xml_candidates:
        for ref in _extract_drawable_refs_from_xml(xml_file):
            for ext in ('.png', '.webp', '.svg'):
                for match in res_index.get(f'{ref}{ext}', ()):
                    if _is_valid_icon_file(match):
                        return match
            for nested in res_index.get(f'{ref}.xml', ()):
                for sub_ref in _extract_drawable_refs_from_xml(nested):
                    for ext in ('.png', '.webp', '.svg'):
                        for match in res_index.get(f'{sub_ref}{ext}', ()):
                            if _is_valid_icon_file(match):
                                return match

    xml_fallbacks = [
        *(f'{stem}.xml' for stem in manifest_icon_names),
        'ic_launcher.xml',
        'ic_launcher_round.xml',
    ]
    for fname in xml_fallbacks:
        for xml_path in res_index.get(fname, ()):
            path = Path(xml_path)
            if path.is_file() and not is_pipe_or_link(path):
                return path.as_posix()

    return ''


def get_icon_from_src(app_dic, icon_from_mfst):
    res_path = ''
    eclipse = Path(app_dic['app_dir']) / 'res'
    studio = Path(app_dic['app_dir']) / 'app' / 'src' / 'main' / 'res'
    if eclipse.exists():
        res_path = eclipse.as_posix()
    elif studio.exists():
        res_path = studio.as_posix()
    if not res_path:
        return

    icon_file = find_icon_path_zip(
        app_dic['md5'],
        res_path,
        icon_from_mfst)
    if (icon_file
            and _is_valid_icon_file(icon_file)
            and _is_safe_icon_path(app_dic['app_dir'], icon_file)):
        dwd = Path(settings.DWD_DIR)
        out = dwd / (app_dic['md5'] + '-icon' + Path(icon_file).suffix.lower())
        copy2(icon_file, out)
        app_dic['icon_path'] = out.name


def find_icon_path_zip(checksum, res_dir, icon_paths_from_manifest):
    """
    Find icon.

    Tries to find an icon, based on paths
    fetched from the manifest and by global search
    returns an empty string on fail or a full path
    """
    try:
        msg = 'Guessing icon path'
        logger.info(msg)
        append_scan_status(checksum, msg)
        for icon_path in icon_paths_from_manifest:
            if not icon_path or icon_path == '@null':
                continue
            if is_path_traversal(icon_path):
                logger.warning(
                    'Path traversal detected in icon path: %s',
                    sanitize_for_logging(icon_path),
                )
                continue
            if icon_path.startswith('@'):
                path_array = icon_path.strip('@').split(os.sep)
                rel_path = os.sep.join(path_array[1:])
                for size_str in KNOWN_MIPMAP_SIZES:
                    for ext in ('.png', '.webp'):
                        tmp_path = os.path.join(
                            res_dir,
                            path_array[0] + size_str,
                            rel_path + ext)
                        if not is_safe_path(res_dir, tmp_path, icon_path):
                            continue
                        if _is_valid_icon_file(tmp_path):
                            return tmp_path
            elif icon_path.startswith(('res/', '/res/')):
                # Use removeprefix-style stripping to remove only the res/ prefix,
                # not a character set (str.strip('/res') strips chars {/,r,e,s}).
                rel = icon_path.lstrip('/')
                if rel.startswith('res/'):
                    rel = rel[len('res/'):]
                full_path = os.path.join(res_dir, rel)
                if not is_safe_path(res_dir, full_path, icon_path):
                    continue
                if _is_valid_icon_file(full_path):
                    return full_path
                for ext in ('.png', '.webp'):
                    ext_path = full_path + ext
                    if not is_safe_path(res_dir, ext_path, icon_path):
                        continue
                    if _is_valid_icon_file(ext_path):
                        return ext_path

            file_name = icon_path.split(os.sep)[-1]
            search_names = (
                (file_name,)
                if file_name.endswith(('.png', '.webp'))
                else (f'{file_name}.png', f'{file_name}.webp')
            )
            for sname in search_names:
                for guess in _search_folder(res_dir, sname):
                    if _is_valid_icon_file(guess):
                        return guess

        # If didn't find, try the default name.. returns empty if not find
        return guess_icon_path(res_dir)

    except Exception as exp:
        msg = 'Failed to find icon path'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def get_icon_apk_res(app_dic):
    """Get icon path from APK resource."""
    icon_src = ''
    checksum = app_dic['md5']
    try:
        msg = 'Fetching icon path'
        logger.info(msg)
        append_scan_status(checksum, msg)
        app_dir = Path(app_dic['app_dir'])
        res_path = app_dir / 'res'
        apktool_res_path = app_dir / 'apktool_out' / 'res'
        icon_name = None

        # If icon is found in androguard or aapt2
        icon_name = app_dic.get('androguard_apk_icon') or app_dic.get(
            'apk_features', {}).get('application_icon')
        if icon_name == '@null':
            icon_name = None
        if is_path_traversal(icon_name):
            logger.warning('Path traversal detected in icon path')
            icon_name = None
        # Handle reserved file names case
        if icon_name and any(
                icon_name.startswith(x) for x in RESERVED_FILE_NAMES):
            icon_name = str(Path('_conflict_') / icon_name)
        if (icon_name
                and not is_safe_path(
                    app_dir, app_dir / icon_name, icon_name)):
            logger.warning('Icon path escapes application directory')
            icon_name = None

        # androguard/aapt2 cannot find icon file, fallback to res or apktool.
        if not res_path.exists() and apktool_res_path.exists() and not icon_name:
            logger.warning('Cannot find res directory,'
                           ' fallback to apktool res directory')
            try:
                copytree(
                    apktool_res_path,
                    res_path,
                    symlinks=True,
                    dirs_exist_ok=True,
                )
            except Exception:
                pass
        if not icon_name:
            icon_name = ''
            logger.warning('androguard/aapt2 cannot find icon resource')
            guessed = guess_icon_path(str(res_path))
            if guessed:
                try:
                    icon_name = Path(guessed).relative_to(app_dir).as_posix()
                except ValueError:
                    icon_name = guessed
                icon_src = guessed
        elif icon_name and not icon_name.endswith('.xml'):
            candidate = app_dir / icon_name
            if _is_valid_icon_file(candidate):
                icon_src = candidate.as_posix()
            else:
                guessed = guess_icon_path(str(res_path))
                if guessed and guessed.endswith('.xml'):
                    try:
                        icon_name = Path(guessed).relative_to(app_dir).as_posix()
                    except ValueError:
                        icon_name = guessed
                else:
                    icon_src = guessed

        if icon_name and icon_name.endswith('.xml'):
            # Handle XML icon case
            apktool_res = False
            # Can be vector XML/XML pointing to vector files
            # Convert AXML to XML for vector
            if not convert_axml_to_xml(app_dir, icon_name):
                # not vector, but adaptive icon
                # need parsing, let's use apktool res
                apktool_res = True
            # Attempt to generate svg(s) from avg(s)
            convert_vector_to_svg(
                app_dir,
                icon_name,
                apktool_res)
            xpath = app_dir / icon_name
            ipath = xpath.parent / (xpath.stem + '.svg')
            if _is_valid_icon_file(ipath):
                # When icon xml is a vector
                icon_path = ipath.as_posix()
            else:
                # When icon xml point to other vector files
                icon_path = get_icon_svg_from_xml(app_dir, icon_name)
            if icon_path and _is_valid_icon_file(icon_path):
                icon_src = icon_path
            else:
                # if we cannot find from xml
                icon_src = guess_icon_path(str(res_path))

        # Log warning if correct icon is not found
        if icon_src.endswith('.xml'):
            logger.warning('Cannot find icon file from xml')
            icon_src = ''
        elif not icon_src.endswith(('.png', '.svg', '.webp')):
            logger.warning('Cannot find a valid icon file')
            icon_src = ''
        if not icon_name:
            logger.warning('Cannot find icon file')
            icon_src = ''
        return icon_src
    except Exception as exp:
        msg = 'Failed to fetch icon path'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return icon_src


def get_icon_apk(app_dic):
    """Get/Guess icon from APK binary."""
    app_dic['icon_path'] = ''
    try:
        # Icon lookup in res directory
        icon_file = get_icon_apk_res(app_dic)
        if icon_file:
            src = Path(icon_file)
            # Copy PNG/SVG to Downloads
            icon = app_dic['md5'] + '-icon' + src.suffix.lower()
            out = Path(settings.DWD_DIR) / icon
            if (src.exists()
                    and src.is_file()
                    and _is_safe_icon_path(app_dic['app_dir'], src)):
                copy2(src.as_posix(), out.as_posix())
                app_dic['icon_path'] = out.name
    except Exception:
        logger.exception('Failed to get icon from APK')


# PNG icon lookup functions above ^
# SVG/XML icon lookup functions below


def transform_svg(fpath, bpath, output):
    """Transform SVG from foreground and background."""
    try:
        if not (_is_valid_icon_file(fpath) and _is_valid_icon_file(bpath)):
            return None
        parser = etree.XMLParser(resolve_entities=False, no_network=True)
        background = etree.parse(bpath, parser=parser)
        logo = etree.parse(fpath, parser=parser)
        bg_root = background.getroot()
        logo_root = logo.getroot()
        if not len(logo_root):
            return None
        attrib = {'transform': 'translate(1, 1)'}
        if 'class' in logo_root.attrib:
            attrib['class'] = logo_root.attrib['class']
        group = etree.SubElement(
            bg_root,
            '{http://www.w3.org/2000/svg}g',
            attrib=attrib,
        )
        for child in logo_root:
            local = (
                child.tag.split('}')[-1]
                if isinstance(child.tag, str) else ''
            )
            if local == 'defs':
                bg_root.insert(0, child)
            else:
                group.append(child)
        background.write(
            output,
            xml_declaration=True,
            standalone=True,
            pretty_print=True,
        )
        return output.as_posix()
    except Exception:
        return None


def _resolve_adaptive_icon_xml(app_dir, icon_xml_file):
    """Return the readable adaptive-icon XML Path in apktool_out or app_dir."""
    if not is_safe_path(app_dir, app_dir / icon_xml_file, icon_xml_file):
        return None
    rel_xml = Path(icon_xml_file)
    if rel_xml.parts and rel_xml.parts[0] == 'apktool_out':
        apktool_candidate = app_dir / rel_xml
    else:
        apktool_candidate = app_dir / 'apktool_out' / rel_xml
    if apktool_candidate.is_file() and not is_pipe_or_link(apktool_candidate):
        return apktool_candidate
    apktool_res = app_dir / 'apktool_out' / 'res'
    if apktool_res.exists():
        for candidate in apktool_res.glob('mipmap-anydpi*/ic_launcher*.xml'):
            if candidate.is_file() and not is_pipe_or_link(candidate):
                return candidate
    direct_candidate = app_dir / icon_xml_file
    if direct_candidate.is_file() and not is_pipe_or_link(direct_candidate):
        return direct_candidate
    return None


def get_icon_svg_from_xml(app_dir, icon_xml_file):
    """
    Parse XML file for icon path.

    Get icon path from XML.
    """
    search_loc = app_dir / 'apktool_out' / 'res' / 'drawable'
    try:
        icon_xml = _resolve_adaptive_icon_xml(app_dir, icon_xml_file)
        if not icon_xml or not search_loc.exists():
            return None
        parsed = parseString(icon_xml.read_text('utf8', 'ignore'))
        foreground = parsed.getElementsByTagName('foreground')
        background = parsed.getElementsByTagName('background')
        ficon = foreground[0].getAttribute(
            'android:drawable').rsplit('/', 1)[1].strip()
        bicon = background[0].getAttribute(
            'android:drawable').rsplit('/', 1)[1].strip()
        if is_path_traversal(ficon) or is_path_traversal(bicon):
            return None
        fpath = search_loc / f'{ficon}.svg'
        bpath = search_loc / f'{bicon}.svg'
        if (not is_safe_path(search_loc, fpath, f'{ficon}.svg')
                or not is_safe_path(search_loc, bpath, f'{bicon}.svg')
                or not (_is_valid_icon_file(fpath) and _is_valid_icon_file(bpath))):
            return None
        output = search_loc / f'{icon_xml.stem}.svg'
        return transform_svg(fpath, bpath, output)
    except Exception:
        try:
            if not search_loc.exists():
                return None
            fsvg = search_loc / 'ic_launcher_foreground.svg'
            bsvg = search_loc / 'ic_launcher_background.svg'
            if _is_valid_icon_file(fsvg) and _is_valid_icon_file(bsvg):
                output = search_loc / 'ic_launcher.svg'
                return transform_svg(fsvg, bsvg, output)
            return None
        except Exception:
            logger.exception('Guessing icon svg')
    return None


def convert_axml_to_xml(app_dir, icon_file):
    """Convert AXML to XML for icons from /res."""
    try:
        logger.info('Converting icon axml to xml')
        icon_bin_xml = app_dir / icon_file
        if (not is_safe_path(app_dir, icon_bin_xml, icon_file)
                or is_pipe_or_link(icon_bin_xml)):
            return None
        out_xml = app_dir / icon_file
        raw = icon_bin_xml.read_bytes()
        if raw.lstrip().startswith(b'<'):
            DefusedET.fromstring(raw, forbid_dtd=True)
            xml_txt = raw
        else:
            aobj = axml.AXMLPrinter(raw).get_xml_obj()
            if aobj is None:
                return False
            xml_txt = etree.tostring(
                aobj, pretty_print=True, encoding='utf-8')
        for sys_color, hex_color in ANDROID_SYSTEM_COLORS:
            xml_txt = xml_txt.replace(sys_color, hex_color)
        out_xml.write_bytes(xml_txt)
        if b'<adaptive-icon' in xml_txt:
            return False
        return True
    except Exception:
        logger.exception('Failed to convert axml to xml')


def _collect_vector_xml_names(app_dir, icon_name, drawable_dir):
    """Return vector XML filenames in drawable_dir referenced by the icon."""
    if not drawable_dir.is_dir():
        return []
    queue = [
        Path(icon_name).name,
        'ic_launcher.xml',
        'ic_launcher_foreground.xml',
        'ic_launcher_background.xml',
    ]
    icon_xml = _resolve_adaptive_icon_xml(app_dir, icon_name)
    if icon_xml:
        queue.append(icon_xml.name)
        for ref in _extract_drawable_refs_from_xml(icon_xml):
            queue.append(f'{ref}.xml')
    visited = set()
    while queue and len(visited) < 16:
        fname = queue.pop(0)
        if fname in visited or fname.startswith('-'):
            continue
        visited.add(fname)
        fpath = drawable_dir / fname
        if fpath.is_file() and not is_pipe_or_link(fpath):
            for sub_ref in _extract_drawable_refs_from_xml(fpath):
                sub_name = f'{sub_ref}.xml'
                if sub_name not in visited:
                    queue.append(sub_name)
    vector_files = []
    for fname in sorted(visited):
        fpath = drawable_dir / fname
        if not fpath.is_file() or is_pipe_or_link(fpath):
            continue
        try:
            raw = fpath.read_bytes()
            if b'<vector' not in raw:
                continue
            modified = raw
            for sys_color, hex_color in ANDROID_SYSTEM_COLORS:
                modified = modified.replace(sys_color, hex_color)
            if modified != raw:
                fpath.write_bytes(modified)
            vector_files.append(fname)
        except OSError:
            continue
    return vector_files


ANDROID_NS = '{http://schemas.android.com/apk/res/android}'
AAPT_NS = '{http://schemas.android.com/aapt}'
SVG_NS = 'http://www.w3.org/2000/svg'
_MAX_VECTOR_BYTES = 1_500_000
_MAX_VECTOR_PATHS = 256
_MAX_PATH_DATA = 200_000
_MAX_DEFS = 32
_PATH_DATA_RE = re.compile(r'[A-Za-z0-9eE.,+\-\s]+')
_NUMBER_RE = re.compile(
    r'\s*(-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)'
    r'(?:dip|dp|sp|px|in|mm|pt)?\s*')
_SPREAD_MAP = {
    '0': 'pad',
    '1': 'repeat',
    '2': 'reflect',
    'clamp': 'pad',
    'mirror': 'reflect',
    'repeat': 'repeat',
}
_FILL_RULE_MAP = {
    '0': 'nonzero',
    '1': 'evenodd',
    'evenodd': 'evenodd',
    'nonzero': 'nonzero',
}
_LINECAP_MAP = {
    '0': 'butt',
    '1': 'round',
    '2': 'square',
    'butt': 'butt',
    'round': 'round',
    'square': 'square',
}
_LINEJOIN_MAP = {
    '0': 'miter',
    '1': 'round',
    '2': 'bevel',
    'bevel': 'bevel',
    'miter': 'miter',
    'round': 'round',
}


def _enum_token(value, default=''):
    """Normalize a symbolic or decimal/hex integer Android enum value."""
    if value is None:
        return default
    token = str(value).strip().lower()
    if not token:
        return default
    if (token.startswith(('0x', '-0x', '+0x'))
            or token.lstrip('+-').isdigit()):
        try:
            return str(int(token, 0))
        except ValueError:
            return token
    return token


def _xml_local(tag):
    """Return the local name of an ElementTree tag."""
    if not isinstance(tag, str):
        return ''
    return tag.rsplit('}', 1)[-1]


def _android_attr(elem, name, default=None):
    """Read an attribute in the Android namespace or bare form."""
    val = elem.get(f'{ANDROID_NS}{name}')
    if val is None:
        val = elem.get(f'android:{name}')
    if val is None:
        val = elem.get(name)
    return default if val is None else val


def _vec_number(value, default=None, resources=None):
    """Parse a bounded finite Android dimension or float."""
    if isinstance(value, str) and resources and value.strip().startswith('@'):
        value = _resolve_resource_text(
            value, resources, ('dimen', 'integer', 'fraction'))
    if not isinstance(value, str):
        return default
    match = _NUMBER_RE.fullmatch(value)
    if not match:
        return default
    number = float(match.group(1))
    if not math.isfinite(number) or abs(number) > 1_000_000:
        return default
    return number


def _parse_hex_color(value):
    """Convert #RGB/#ARGB/#RRGGBB/#AARRGGBB to (rgb_hex, alpha)."""
    if not isinstance(value, str):
        return None, None
    color = value.strip()
    if not re.fullmatch(r'#[0-9A-Fa-f]{3,8}', color):
        return None, None
    digits = color[1:]
    if len(digits) == 3:
        return f'#{digits}', 1.0
    if len(digits) == 4:
        return f'#{digits[1:]}', int(digits[0] * 2, 16) / 255.0
    if len(digits) == 6:
        return f'#{digits}', 1.0
    if len(digits) == 8:
        return f'#{digits[2:]}', int(digits[:2], 16) / 255.0
    return None, None


def _load_color_resources(values_dir):
    """Load color, string, and dimen mappings from values/*.xml safely."""
    resources = {
        'android:color/transparent': '#00000000',
        'android:color/white': '#FFFFFFFF',
        'android:color/black': '#FF000000',
        'android:0106000d': '#00000000',
        'android:0106000b': '#FFFFFFFF',
        'android:0106000c': '#FF000000',
    }
    vdir = Path(values_dir)
    if not vdir.is_dir() or is_pipe_or_link(vdir):
        return resources
    res_types = ('color', 'string', 'dimen', 'integer', 'fraction')
    for xml_file in sorted(vdir.glob('*.xml'))[:64]:
        if not xml_file.is_file() or is_pipe_or_link(xml_file):
            continue
        try:
            if xml_file.stat().st_size > _MAX_VECTOR_BYTES:
                continue
            root = DefusedET.fromstring(
                xml_file.read_bytes(), forbid_dtd=True)
        except Exception:
            continue
        for node in root.iter():
            tag = _xml_local(node.tag)
            kind = node.get('type') if tag == 'item' else tag
            if kind not in res_types:
                continue
            name = (node.get('name') or '').strip()
            text = (node.text or '').strip()
            if not name or not text:
                continue
            resources[f'{kind}/{name}'] = text
            if kind == 'color':
                resources[name] = text
    return resources


def _resolve_resource_text(raw, resources, allowed_kinds):
    """Resolve an @<kind>/<name> reference chain within resources."""
    if not isinstance(raw, str) or not resources:
        return None
    cur = raw.strip()
    seen = set()
    while cur.startswith('@') and len(seen) < 8:
        if cur in seen:
            return None
        seen.add(cur)
        ref = cur[1:]
        if '/' not in ref:
            return None
        kind, key = ref.split('/', 1)
        if kind not in allowed_kinds:
            return None
        nxt = resources.get(f'{kind}/{key}')
        if nxt is None:
            return None
        cur = nxt.strip()
    return None if cur.startswith('@') else cur


def _resolve_color_value(raw, colors):
    """Resolve literal hex or @color/... chain to (rgb_hex, alpha)."""
    if not isinstance(raw, str):
        return None, None
    cur = raw.strip()
    seen = set()
    while cur.startswith('@') and len(seen) < 8:
        norm = cur.lower()
        if norm in seen:
            return None, None
        seen.add(norm)
        ref = cur[1:]
        if ref.lower() in colors:
            cur = colors[ref.lower()].strip()
            continue
        if ref in colors:
            cur = colors[ref].strip()
            continue
        if '/' in ref:
            kind, key = ref.split('/', 1)
            if kind in ('color', 'android:color') and key in colors:
                cur = colors[key].strip()
                continue
        return None, None
    return _parse_hex_color(cur)


def _group_transform(elem):
    """Build an SVG transform string from an Android <group> element."""
    tx = _vec_number(_android_attr(elem, 'translateX'), 0.0)
    ty = _vec_number(_android_attr(elem, 'translateY'), 0.0)
    rot = _vec_number(_android_attr(elem, 'rotation'), 0.0)
    px = _vec_number(_android_attr(elem, 'pivotX'), 0.0)
    py = _vec_number(_android_attr(elem, 'pivotY'), 0.0)
    sx = _vec_number(_android_attr(elem, 'scaleX'), 1.0)
    sy = _vec_number(_android_attr(elem, 'scaleY'), 1.0)
    parts = []
    if tx or ty:
        parts.append(f'translate({tx:g} {ty:g})')
    if rot:
        parts.append(
            f'rotate({rot:g} {px:g} {py:g})' if (px or py)
            else f'rotate({rot:g})')
    if sx != 1.0 or sy != 1.0:
        if px or py:
            parts.append(f'translate({px:g} {py:g})')
        parts.append(f'scale({sx:g} {sy:g})')
        if px or py:
            parts.append(f'translate({-px:g} {-py:g})')
    return ' '.join(parts)


def _gradient_stops(grad_elem, colors):
    """Extract [(offset_str, hex_color, alpha)] stops from <gradient>."""
    stops = []
    for child in grad_elem:
        if _xml_local(child.tag) != 'item' or len(stops) >= 16:
            continue
        col, alpha = _resolve_color_value(
            _android_attr(child, 'color'), colors)
        off = _vec_number(_android_attr(child, 'offset'))
        if col is None or off is None:
            continue
        off_clamped = max(0.0, min(1.0, off))
        stops.append((f'{off_clamped:g}', col, alpha))
    if stops:
        return stops
    start = _resolve_color_value(_android_attr(grad_elem, 'startColor'), colors)
    end = _resolve_color_value(_android_attr(grad_elem, 'endColor'), colors)
    if start[0] is None or end[0] is None:
        return []
    result = [('0%', start[0], start[1])]
    center = _resolve_color_value(
        _android_attr(grad_elem, 'centerColor'), colors)
    if center[0] is not None:
        result.append(('50%', center[0], center[1]))
    result.append(('100%', end[0], end[1]))
    return result


def _build_svg_gradient(grad_elem, grad_id, colors):
    """Convert an Android <gradient> element to an SVG gradient element."""
    kind = _enum_token(_android_attr(grad_elem, 'type'), 'linear')
    stops = _gradient_stops(grad_elem, colors)
    if len(stops) < 2:
        return None
    spread = _SPREAD_MAP.get(_enum_token(_android_attr(grad_elem, 'tileMode')))
    if kind in ('1', 'radial'):
        cx = _vec_number(_android_attr(grad_elem, 'centerX'), 0.0)
        cy = _vec_number(_android_attr(grad_elem, 'centerY'), 0.0)
        radius = _vec_number(_android_attr(grad_elem, 'gradientRadius'))
        if radius is None or radius <= 0:
            return None
        attrs = {
            'id': grad_id,
            'gradientUnits': 'userSpaceOnUse',
            'cx': f'{cx:g}',
            'cy': f'{cy:g}',
            'r': f'{radius:g}',
        }
        tag = 'radialGradient'
    elif kind in ('0', 'linear', ''):
        attrs = {
            'id': grad_id,
            'gradientUnits': 'userSpaceOnUse',
            'x1': f'{_vec_number(_android_attr(grad_elem, "startX"), 0.0):g}',
            'y1': f'{_vec_number(_android_attr(grad_elem, "startY"), 0.0):g}',
            'x2': f'{_vec_number(_android_attr(grad_elem, "endX"), 0.0):g}',
            'y2': f'{_vec_number(_android_attr(grad_elem, "endY"), 0.0):g}',
        }
        tag = 'linearGradient'
    else:
        return None
    if spread:
        attrs['spreadMethod'] = spread
    svg_grad = XmlElementTree.Element(tag, attrs)
    for offset, stop_color, stop_alpha in stops:
        stop_attrs = {'offset': offset, 'stop-color': stop_color}
        if stop_alpha is not None and stop_alpha < 1.0:
            stop_attrs['stop-opacity'] = f'{max(0.0, stop_alpha):g}'
        XmlElementTree.SubElement(svg_grad, 'stop', stop_attrs)
    return svg_grad


def _external_gradient_paint(raw_ref, drawable_dir, add_def, colors):
    """Resolve @drawable/$... or @color/... external <gradient> XML to url(#id)."""
    if (not drawable_dir
            or not isinstance(raw_ref, str)
            or not raw_ref.strip().startswith('@')
            or '/' not in raw_ref):
        return None
    kind, name = raw_ref.strip()[1:].split('/', 1)
    if (kind not in ('drawable', 'color')
            or not name
            or is_path_traversal(name)
            or any(c in name for c in ('/', '\\', '*', '?', '['))):
        return None
    base = Path(drawable_dir)
    res_root = base.parent
    candidates = [base / f'{name}.xml']
    if res_root.is_dir() and not is_pipe_or_link(res_root):
        for sibling in sorted(res_root.glob(f'{kind}*')):
            cand = sibling / f'{name}.xml'
            if cand != candidates[0]:
                candidates.append(cand)
    for grad_path in candidates[:12]:
        try:
            if (not is_safe_path(res_root, grad_path, grad_path.name)
                    or not grad_path.is_file()
                    or is_pipe_or_link(grad_path)
                    or grad_path.stat().st_size > _MAX_VECTOR_BYTES):
                continue
            groot = DefusedET.fromstring(
                grad_path.read_bytes(), forbid_dtd=True)
        except Exception:
            continue
        if _xml_local(groot.tag) != 'gradient':
            continue
        grad_id = add_def(
            lambda gid, g=groot: _build_svg_gradient(g, gid, colors), 'g')
        if grad_id:
            return f'url(#{grad_id})'
    return None


def _aapt_gradients(path_elem, add_def, colors, drawable_dir=None):
    """Extract inline <aapt:attr> or @drawable/$... gradients for a <path>."""
    paints = {}
    for child in path_elem:
        if _xml_local(child.tag) != 'attr':
            continue
        target = (child.get('name') or '').strip()
        if target.endswith('fillColor'):
            prop = 'fill'
        elif target.endswith('strokeColor'):
            prop = 'stroke'
        else:
            continue
        for sub in child:
            if _xml_local(sub.tag) == 'gradient':
                grad_id = add_def(
                    lambda gid, g=sub: _build_svg_gradient(g, gid, colors),
                    'g',
                )
                if grad_id:
                    paints[prop] = f'url(#{grad_id})'
                break
    for attr_name, prop in (('fillColor', 'fill'), ('strokeColor', 'stroke')):
        if prop in paints:
            continue
        ext = _external_gradient_paint(
            _android_attr(path_elem, attr_name),
            drawable_dir,
            add_def,
            colors,
        )
        if ext:
            paints[prop] = ext
    return paints


def _apply_path_paint(elem, attrs, aapt_paints, colors):
    """Populate SVG fill and stroke attributes for one Android <path>."""
    fill_rule = _FILL_RULE_MAP.get(
        _enum_token(_android_attr(elem, 'fillType')))
    if fill_rule:
        attrs['fill-rule'] = fill_rule

    raw_fill = _android_attr(elem, 'fillColor')
    if 'fill' in aapt_paints:
        attrs['fill'] = aapt_paints['fill']
        fill_alpha = _vec_number(
            _android_attr(elem, 'fillAlpha'), 1.0, colors)
        if fill_alpha < 1.0:
            attrs['fill-opacity'] = f'{max(0.0, fill_alpha):g}'
    elif raw_fill is not None:
        fill_col, col_alpha = _resolve_color_value(raw_fill, colors)
        if fill_col:
            attrs['fill'] = fill_col
            explicit = _vec_number(
                _android_attr(elem, 'fillAlpha'), 1.0, colors)
            combined = max(0.0, min(1.0, col_alpha * explicit))
            if combined < 1.0:
                attrs['fill-opacity'] = f'{combined:g}'
        else:
            attrs['fill'] = 'none'
    else:
        attrs['fill'] = 'none'

    raw_stroke = _android_attr(elem, 'strokeColor')
    stroke_paint = aapt_paints.get('stroke')
    stroke_col, stroke_col_alpha = (
        (stroke_paint, 1.0) if stroke_paint
        else _resolve_color_value(raw_stroke, colors)
    )
    if not stroke_col:
        return
    attrs['stroke'] = stroke_col
    width = _vec_number(_android_attr(elem, 'strokeWidth'), 0.0, colors)
    attrs['stroke-width'] = f'{max(0.0, width):g}'
    explicit_s = _vec_number(
        _android_attr(elem, 'strokeAlpha'), 1.0, colors)
    combined_s = max(0.0, min(1.0, stroke_col_alpha * explicit_s))
    if combined_s < 1.0:
        attrs['stroke-opacity'] = f'{combined_s:g}'
    linecap = _LINECAP_MAP.get(
        _enum_token(_android_attr(elem, 'strokeLineCap')))
    if linecap:
        attrs['stroke-linecap'] = linecap
    linejoin = _LINEJOIN_MAP.get(
        _enum_token(_android_attr(elem, 'strokeLineJoin')))
    if linejoin:
        attrs['stroke-linejoin'] = linejoin
    miter = _vec_number(_android_attr(elem, 'strokeMiterLimit'), None, colors)
    if miter is not None and miter > 0:
        attrs['stroke-miterlimit'] = f'{miter:g}'


def vector_xml_to_svg(
        xml_bytes, colors=None, icon_prefix='', drawable_dir=None):
    """Convert Android VectorDrawable XML bytes to sanitized SVG text."""
    if not xml_bytes or len(xml_bytes) > _MAX_VECTOR_BYTES:
        return None
    try:
        root = DefusedET.fromstring(xml_bytes, forbid_dtd=True)
    except Exception:
        return None
    if _xml_local(root.tag) != 'vector':
        return None
    colors = colors if colors is not None else {}
    vp_w = _vec_number(_android_attr(root, 'viewportWidth'), None, colors)
    vp_h = _vec_number(_android_attr(root, 'viewportHeight'), None, colors)
    if not vp_w or not vp_h or vp_w <= 0 or vp_h <= 0:
        return None
    width = _vec_number(_android_attr(root, 'width'), vp_w, colors)
    height = _vec_number(_android_attr(root, 'height'), vp_h, colors)
    svg_attrs = {
        'xmlns': SVG_NS,
        'version': '1.1',
        'width': f'{(width if width and width > 0 else vp_w):g}',
        'height': f'{(height if height and height > 0 else vp_h):g}',
        'viewBox': f'0 0 {vp_w:g} {vp_h:g}',
    }
    root_alpha = _vec_number(_android_attr(root, 'alpha'), 1.0)
    if 0.0 <= root_alpha < 1.0:
        svg_attrs['opacity'] = f'{root_alpha:g}'
    svg = XmlElementTree.Element('svg', svg_attrs)
    defs = None
    def_count = 0
    path_count = 0
    path_bytes = 0

    def add_def(factory, kind):
        nonlocal defs, def_count
        if def_count >= _MAX_DEFS:
            return None
        ident = f'{icon_prefix}{kind}{def_count}'
        elem = factory(ident)
        if elem is None:
            return None
        if defs is None:
            defs = XmlElementTree.Element('defs')
            svg.insert(0, defs)
        defs.append(elem)
        def_count += 1
        return ident

    def resolve_path_data(elem):
        data = _android_attr(elem, 'pathData')
        if isinstance(data, str) and data.strip().startswith('@'):
            data = _resolve_resource_text(data, colors, ('string',))
        if (not isinstance(data, str)
                or not data
                or len(data) > _MAX_PATH_DATA
                or not _PATH_DATA_RE.fullmatch(data)):
            return None
        return data

    def build_clip(clip_elem, clip_id):
        data = resolve_path_data(clip_elem)
        if not data:
            return None
        cp = XmlElementTree.Element('clipPath', {'id': clip_id})
        path_attrs = {'d': data}
        clip_rule = _FILL_RULE_MAP.get(
            _enum_token(_android_attr(clip_elem, 'fillType')))
        if clip_rule:
            path_attrs['clip-rule'] = clip_rule
        XmlElementTree.SubElement(cp, 'path', path_attrs)
        return cp

    def convert_children(src_parent, dst_parent):
        nonlocal path_count, path_bytes
        active_dst = dst_parent
        for child in src_parent:
            tag = _xml_local(child.tag)
            if tag == 'clip-path':
                cid = add_def(
                    lambda gid, c=child: build_clip(c, gid), 'c')
                if cid:
                    active_dst = XmlElementTree.SubElement(
                        active_dst, 'g', {'clip-path': f'url(#{cid})'})
                continue
            if tag == 'group':
                grp = XmlElementTree.SubElement(active_dst, 'g')
                transform = _group_transform(child)
                if transform:
                    grp.set('transform', transform)
                convert_children(child, grp)
                continue
            if tag != 'path' or path_count >= _MAX_VECTOR_PATHS:
                continue
            data = resolve_path_data(child)
            if not data:
                continue
            path_bytes += len(data)
            if path_bytes > _MAX_PATH_DATA:
                return
            p_attrs = {'d': data}
            aapt_paints = _aapt_gradients(
                child, add_def, colors, drawable_dir)
            _apply_path_paint(child, p_attrs, aapt_paints, colors)
            XmlElementTree.SubElement(active_dst, 'path', p_attrs)
            path_count += 1

    convert_children(root, svg)
    if not path_count or path_bytes > _MAX_PATH_DATA:
        return None
    rendered = XmlElementTree.tostring(svg, encoding='unicode')
    cleaned = sanitize_svg(rendered)
    return cleaned or None


def convert_vector_to_svg(app_dir, icon_name, apktool_res):
    """Convert Android vector drawable XML(s) to SVG in pure Python."""
    try:
        values = app_dir / 'res' / 'values'
        direct = app_dir / icon_name
        if not is_safe_path(app_dir, direct, icon_name):
            return
        base_dir = direct.parent

        if apktool_res:
            values = app_dir / 'apktool_out' / 'res' / 'values'
            drawable = app_dir / 'apktool_out' / 'res' / 'drawable'
            base_dir = drawable
            files = _collect_vector_xml_names(app_dir, icon_name, drawable)
            if not files:
                return
        else:
            if direct.name.startswith('-'):
                return
            files = [direct.name]

        colors = _load_color_resources(values)
        for idx, fname in enumerate(files):
            xml_path = base_dir / fname
            if (not is_safe_path(base_dir, xml_path, fname)
                    or not xml_path.is_file()
                    or is_pipe_or_link(xml_path)):
                continue
            svg_text = vector_xml_to_svg(
                xml_path.read_bytes(),
                colors=colors,
                icon_prefix=f'v{idx}_',
                drawable_dir=base_dir,
            )
            if not svg_text:
                continue
            svg_path = xml_path.with_suffix('.svg')
            if (is_safe_path(base_dir, svg_path, svg_path.name)
                    and not is_pipe_or_link(svg_path)):
                svg_path.write_text(svg_text, encoding='utf-8')
    except Exception:
        logger.exception('Android vector to svg conversion failed')
