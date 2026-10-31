# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import fnmatch
import logging
import os
from shutil import copy2, copytree
from pathlib import Path
import subprocess

from defusedxml.minidom import parseString

from lxml import etree

from django.conf import settings

from mobsf.MobSF.security import (
    is_path_traversal,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    find_java_binary,
    is_file_exists,
)
from mobsf.StaticAnalyzer.tools.androguard4 import (
    axml,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    RESERVED_FILE_NAMES,
)


logger = logging.getLogger(__name__)


# relative to res folder
KNOWN_PATHS = [
    'mipmap-hdpi',
    'mipmap-xhdpi',
    'drawable-hdpi',
    'drawable-xhdpi',
    'mipmap-mdpi',
    'drawable-mdpi',
    'mipmap-hdpi-v4',
]

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
        if not path.is_file() or path.stat().st_size == 0:
            return False
        suffix = path.suffix.lower()
        if suffix == '.png':
            with path.open('rb') as fp:
                return fp.read(8) == PNG_MAGIC
        if suffix == '.webp':
            with path.open('rb') as fp:
                header = fp.read(12)
                return header[:4] == b'RIFF' and header[8:12] == b'WEBP'
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


def _is_safe_icon_path(root, icon_file):
    """Verify a resolved icon path remains inside its application root."""
    try:
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
        parsed = parseString(Path(xml_path).read_text('utf8', 'ignore'))
        for tag in ('foreground', 'monochrome', 'item', 'bitmap', 'background'):
            for node in parsed.getElementsByTagName(tag):
                for attr in ('android:drawable', 'android:src'):
                    val = node.getAttribute(attr)
                    if val and '/' in val:
                        name = val.rsplit('/', 1)[1].strip()
                        if name and name not in refs:
                            refs.append(name)
    except Exception:
        pass
    return refs


def guess_icon_path(res_dir):
    res_path = Path(res_dir)
    apktool_res = res_path.parent / 'apktool_out' / 'res'
    search_roots = [res_path]
    if apktool_res.exists() and apktool_res != res_path:
        search_roots.append(apktool_res)

    icon_folders = [
        'mipmap-xxxhdpi',
        'mipmap-xxhdpi',
        'mipmap-xhdpi',
        'mipmap-hdpi',
        'mipmap-hdpi-v4',
        'mipmap-mdpi',
        'drawable',
    ]
    for root in search_roots:
        for icon_folder in icon_folders:
            for candidate_name in (
                'ic_launcher.png',
                'ic_launcher.webp',
                'ic_launcher_round.png',
                'ic_launcher_foreground.png',
            ):
                guessed = root / icon_folder / candidate_name
                if _is_valid_icon_file(guessed):
                    return guessed.as_posix()

    for root in search_roots:
        for pattern in ('ic_launcher.*', 'ic_launcher*'):
            for guess in _search_folder(root.as_posix(), pattern):
                if _is_valid_icon_file(guess):
                    return guess

    # Check adaptive-icon / layer-list XMLs in apktool_out/res for referenced PNGs
    if apktool_res.exists():
        xml_candidates = list(apktool_res.rglob('ic_launcher*.xml'))
        for xml_file in xml_candidates:
            for ref in _extract_drawable_refs_from_xml(xml_file):
                for ext in ('.png', '.webp', '.svg'):
                    for match in _search_folder(
                            apktool_res.as_posix(), f'{ref}{ext}'):
                        if _is_valid_icon_file(match):
                            return match
                nested_xmls = _search_folder(
                    apktool_res.as_posix(), f'{ref}.xml')
                for nested in nested_xmls:
                    for sub_ref in _extract_drawable_refs_from_xml(nested):
                        for ext in ('.png', '.webp', '.svg'):
                            for match in _search_folder(
                                    apktool_res.as_posix(), f'{sub_ref}{ext}'):
                                if _is_valid_icon_file(match):
                                    return match

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
            and Path(icon_file).exists()
            and _is_safe_icon_path(res_path, icon_file)):
        dwd = Path(settings.DWD_DIR)
        out = dwd / (app_dic['md5'] + '-icon' + Path(icon_file).suffix)
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
            if is_path_traversal(icon_path):
                logger.warning('Path traversal detected in icon path: %s', icon_path)
                continue
            if icon_path.startswith('@'):
                path_array = icon_path.strip('@').split(os.sep)
                rel_path = os.sep.join(path_array[1:])
                for size_str in KNOWN_MIPMAP_SIZES:
                    tmp_path = os.path.join(
                        res_dir, path_array[0] + size_str, rel_path + '.png')
                    if not is_safe_path(res_dir, tmp_path, icon_path):
                        continue
                    if os.path.exists(tmp_path):
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
                if os.path.exists(full_path):
                    return full_path
                full_path += '.png'
                if not is_safe_path(res_dir, full_path, icon_path):
                    continue
                if os.path.exists(full_path):
                    return full_path

            file_name = icon_path.split(os.sep)[-1]
            if file_name.endswith('.png'):
                file_name += '.png'

            for guess in _search_folder(res_dir, file_name):
                if os.path.exists(guess):
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
                copytree(apktool_res_path, res_path, dirs_exist_ok=True)
            except Exception:
                pass
        if res_path.exists() and not icon_name:
            icon_name = ''
            logger.warning('androguard/aapt2 cannot find icon resource')
            icon_name = guess_icon_path(str(res_path))
            icon_src = icon_name

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
                app_dic['tools_dir'],
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
        elif icon_name:
            # We found png icon, the easy path
            candidate = app_dir / icon_name
            if _is_valid_icon_file(candidate):
                icon_src = candidate.as_posix()
            else:
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
        parser = etree.XMLParser(resolve_entities=False, no_network=True)
        background = etree.parse(bpath, parser=parser)
        logo = etree.parse(fpath, parser=parser)
        bg_root = background.getroot()
        logo_root = logo.getroot()
        attrib = {'transform': 'translate(1, 1)'}
        if 'class' in logo_root.attrib:
            attrib['class'] = logo_root.attrib['class']
        group = etree.SubElement(
            bg_root,
            '{http://www.w3.org/2000/svg}g',
            attrib=attrib,
        )
        for child in logo_root:
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


def get_icon_svg_from_xml(app_dir, icon_xml_file):
    """
    Parse XML file for icon path.

    Get icon path from XML.
    """
    try:
        icon_xml = app_dir / 'apktool_out' / icon_xml_file
        if not is_safe_path(app_dir, icon_xml, icon_xml_file):
            return None
        parsed = parseString(icon_xml.read_text('utf8', 'ignore'))
        foreground = parsed.getElementsByTagName('foreground')
        background = parsed.getElementsByTagName('background')
        ficon = foreground[0].getAttribute(
            'android:drawable').rsplit('/', 1)[1]
        bicon = background[0].getAttribute(
            'android:drawable').rsplit('/', 1)[1]
        fpath, bpath = None, None
        for f in icon_xml.parent.rglob('*.svg'):
            if ficon in f.name:
                fpath = f
            if bicon in f.name:
                bpath = f
            if fpath and bpath:
                break
        # To not break existing users
        output = icon_xml.parent / f'{icon_xml.stem}.svg'
        return transform_svg(fpath, bpath, output)
    except Exception:
        try:
            fsvg, bsvg = None, None
            search_loc = app_dir / 'apktool_out' / 'res' / 'drawable'
            if not search_loc.exists():
                return None
            for f in search_loc.rglob('*.svg'):
                if 'ic_launcher_foreground.svg' in f.name:
                    fsvg = f
                if 'ic_launcher_background.svg' in f.name:
                    bsvg = f
                if fsvg and bsvg:
                    break
            if fsvg and bsvg:
                output = search_loc / 'ic_launcher.svg'
                return transform_svg(fsvg, bsvg, output)
            return None
        except Exception:
            logger.exception('Guessing icon svg')


def convert_axml_to_xml(app_dir, icon_file):
    """Convert AXML to XML for icons from /res."""
    try:
        logger.info('Converting icon axml to xml')
        icon_bin_xml = app_dir / icon_file
        if not is_safe_path(app_dir, icon_bin_xml, icon_file):
            return None
        out_xml = app_dir / icon_file
        aobj = axml.AXMLPrinter(
            icon_bin_xml.read_bytes()).get_xml_obj()
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


def convert_vector_to_svg(app_dir, tools_dir, icon_name, apktool_res):
    """Convert android vector graphics to svg."""
    try:
        fnull = open(os.devnull, 'w')
        userbin = getattr(settings, 'VD2SVG_BINARY', '')
        if userbin and is_file_exists(userbin):
            vd2svg = userbin
        else:
            vd2svg = Path(tools_dir) / 'vd2svg-0.4.4.jar'
        # When xml is android vector
        values = app_dir / 'res' / 'values'
        direct = app_dir / icon_name
        if not is_safe_path(app_dir, direct, icon_name):
            return
        cwd = direct.parent.as_posix()

        # When xml is referencing to vector use apktool_res
        files = []
        if apktool_res:
            values = app_dir / 'apktool_out' / 'res' / 'values'
            drawable = app_dir / 'apktool_out' / 'res' / 'drawable'
            cwd = drawable.as_posix()
            for f in drawable.parent.rglob('*.xml'):
                files.append(f.name)
        # Pass xml filename(s) and set cwd as parent
        args = [
            find_java_binary(),
            '-jar',
            vd2svg.as_posix(),
            '-r',
            values.as_posix(),
        ]
        if files:
            args.extend(files)
        else:
            args.extend([direct.name])
        subprocess.run(
            args,
            stdout=fnull,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            timeout=30)
    except Exception:
        logger.exception('Android vector to svg conversion failed')
