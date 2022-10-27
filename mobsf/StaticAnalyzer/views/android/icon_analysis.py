# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import fnmatch
import logging
import os
from shutil import copy2, copytree
from xml.dom import minidom
from pathlib import Path
import subprocess

from lxml import etree

from androguard.core.bytecodes import (
    apk,
    axml,
)

from django.conf import settings

from mobsf.MobSF.utils import (
    find_java_binary,
    is_file_exists,
)


logger = logging.getLogger(__name__)
logging.getLogger('androguard').setLevel(logging.ERROR)


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


def _search_folder(src, file_pattern):
    matches = []
    for root, _, filenames in os.walk(src):
        for filename in fnmatch.filter(filenames, file_pattern):
            matches.append(os.path.join(root, filename))
    return matches


def guess_icon_path(res_dir):
    icon_folders = [
        'mipmap-hdpi',
        'mipmap-hdpi-v4',
        'drawable',
    ]
    for icon_path in icon_folders:
        guessed_icon_path = os.path.join(res_dir, icon_path, 'ic_launcher.png')
        if os.path.exists(guessed_icon_path):
            return guessed_icon_path

    for guess in _search_folder(res_dir, 'ic_launcher.*'):
        return guess

    for guess in _search_folder(res_dir, 'ic_launcher*'):
        return guess

    return ''


def find_icon_path_zip(res_dir, icon_paths_from_manifest):
    """
    Find icon.

    Tries to find an icon, based on paths
    fetched from the manifest and by global search
    returns an empty string on fail or a full path
    """
    global KNOWN_MIPMAP_SIZES
    try:
        logger.info('Guessing icon path')
        for icon_path in icon_paths_from_manifest:
            if icon_path.startswith('@'):
                path_array = icon_path.strip('@').split(os.sep)
                rel_path = os.sep.join(path_array[1:])
                for size_str in KNOWN_MIPMAP_SIZES:
                    tmp_path = os.path.join(
                        res_dir, path_array[0] + size_str, rel_path + '.png')
                    if os.path.exists(tmp_path):
                        return tmp_path
            elif icon_path.startswith(('res/', '/res/')):
                stripped_relative_path = icon_path.strip(
                    '/res')  # Works for neither /res and res
                full_path = os.path.join(res_dir, stripped_relative_path)
                if os.path.exists(full_path):
                    return full_path
                full_path += '.png'
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

    except Exception:
        logger.exception('Guessing icon path')
# PNG icon lookup functions above ^
# SVG/XML icon lookup functions below


def get_icon_src(app_dic, res_dir):
    """
    Returns a dict with isHidden boolean and a relative path.

    path is a full path (not relative to resource folder)
    """
    try:
        logger.info('Fetching icon path')
        icon_src = ''
        apk_path = app_dic['app_path']
        app_dir = Path(app_dic['app_dir'])
        a = apk.APK(apk_path)
        icon_resolution = 0xFFFE - 1
        icon_name = a.get_app_icon(max_dpi=icon_resolution)
        if not icon_name:
            # androguard cannot find icon file.
            logger.warning('androguard cannot find icon resource')
            icon_name = guess_icon_path(res_dir)
            icon_src = icon_name
        if icon_name and icon_name.endswith('.xml'):
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
            if ipath.exists():
                # When icon xml is a vector
                icon_path = ipath.as_posix()
            else:
                # When icon xml point to other vector files
                icon_path = get_icon_svg_from_xml(
                    app_dir, icon_name)
            if icon_path:
                icon_src = icon_path
            else:
                # if we cannot find from xml
                icon_src = guess_icon_path(res_dir)
        else:
            # We found png icon, the easy path
            icon_src = (app_dir / icon_name).as_posix()
        return icon_src
    except Exception:
        logger.exception('Fetching icon function')


def get_icon_apk(app_dic):
    """Get/Guess icon from APK binary."""
    app_dir = Path(app_dic['app_dir'])
    app_dic['icon_path'] = ''
    app_dic['icon_found'] = False
    app_dic['icon_hidden'] = True

    res_path = app_dir / 'res'
    if not res_path.exists():
        logger.warning('Cannot find res directory,'
                       ' using apktool res directory')
        # If res directory is not found or named differently
        # piggyback on apktool decompiled resources
        try:
            apk_tool_res = app_dir / 'apktool_out' / 'res'
            copytree(apk_tool_res, res_path)
        except Exception:
            pass
    # Set app_dic with icon details
    if res_path.exists():
        # Icon lookup in res directory
        app_dic['icon_path'] = get_icon_src(
            app_dic, res_path.as_posix())
        app_dic['icon_found'] = bool(app_dic['icon_path'])
        app_dic['icon_hidden'] = not app_dic['icon_found']

    if app_dic['icon_path']:
        src = Path(app_dic['icon_path'])
        # Convert SVG icon to PNG
        if src.as_posix().endswith('.svg'):
            src = convert_svg_to_png(src, app_dic['tools_dir'])
        # Copy PNG to Downloads
        out = Path(settings.DWD_DIR) / (app_dic['md5'] + '-icon.png')
        if src and src.exists():
            copy2(src.as_posix(), out.as_posix())


def get_icon_svg_from_xml(app_dir, icon_xml_file):
    """
    Parse XML file for icon path.

    Get icon path from XML.
    """
    try:
        icon_xml = app_dir / 'apktool_out' / icon_xml_file
        parsed = minidom.parseString(
            icon_xml.read_text('utf8', 'ignore'))
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
        import svgutils.transform as sg
        background = sg.fromfile(bpath)
        logo = sg.fromfile(fpath)
        root = logo.getroot()
        root.moveto(1, 1)
        background.append([root])
        output = icon_xml.parent / f'{icon_xml.stem}.svg'
        background.save(output)
        return output.as_posix()
    except Exception:
        return None


def convert_axml_to_xml(app_dir, icon_file):
    """Convert AXML to XML for icons from /res."""
    try:
        logger.info('Converting icon axml to xml')
        icon_bin_xml = app_dir / icon_file
        out_xml = app_dir / icon_file
        aobj = axml.AXMLPrinter(
            icon_bin_xml.read_bytes()).get_xml_obj()
        xml_txt = etree.tostring(
            aobj, pretty_print=True, encoding='utf-8')
        if b'<adaptive-icon' in xml_txt:
            return False
        out_xml.write_bytes(xml_txt)
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
            vd2svg = Path(tools_dir) / 'vd2svg-0.3.3.jar'
        # When xml is android vector
        values = app_dir / 'res' / 'values'
        direct = app_dir / icon_name
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


def convert_svg_to_png(svg_file, tools_dir):
    """Convert SVG to PNG."""
    try:
        fnull = open(os.devnull, 'w')
        userbin = getattr(settings, 'BATIK_BINARY', '')
        if userbin and is_file_exists(userbin):
            batik = userbin
        else:
            batik = Path(tools_dir) / 'batik' / 'batik-rasterizer-1.15.jar'
        out = svg_file.parent / (svg_file.stem + '.png')
        args = [
            find_java_binary(),
            '-jar',
            batik.as_posix(),
            svg_file.as_posix(),
            '-d',
            out.as_posix(),
        ]
        logger.info('Converting icon svg to png')
        subprocess.run(
            args,
            stdout=fnull,
            stderr=subprocess.STDOUT,
            timeout=30)
        return out
    except Exception:
        logger.exception('Icon conversion from svg to png failed')
    return None
