# -*- coding: utf_8 -*-
"""
Shared Functions.

Module providing the shared functions for iOS and Android
"""
import hashlib
import logging
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from django.utils.html import escape
from django.http import HttpResponseRedirect

from mobsf.MobSF import settings
from mobsf.MobSF.security import (
    sanitize_for_logging,
)
from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    EMAIL_REGEX,
    STRINGS_REGEX,
    URL_REGEX,
    append_scan_status,
    is_md5,
    print_n_send_error_response,
    set_permissions,
)
from mobsf.MobSF.views.scanning import (
    add_to_recent_scan,
    handle_uploaded_file,
)
from mobsf.StaticAnalyzer.views.comparer import (
    generic_compare,
)
from mobsf.StaticAnalyzer.views.common.secret_detection import (
    get_secrets,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)


logger = logging.getLogger(__name__)
RESERVED_FILE_NAMES = [
    'AndroidManifest.xml',
    'resources.arsc',
    'META-INF/MANIFEST.MF',
    'META-INF/CERT.SF',
    'META-INF/CERT.RSA',
    'META-INF/CERT.DSA',
    'classes.dex']
for i in range(2, 50):
    RESERVED_FILE_NAMES.append(f'classes{i}.dex')


def hash_gen(checksum, app_path) -> tuple:
    """Generate and return sha1 and sha256 as a tuple."""
    try:
        msg = 'Generating Hashes'
        logger.info(msg)
        append_scan_status(checksum, msg)
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        block_size = 65536
        with open(app_path, mode='rb') as afile:
            buf = afile.read(block_size)
            while buf:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(block_size)
        sha1val = sha1.hexdigest()
        sha256val = sha256.hexdigest()
        return sha1val, sha256val
    except Exception as exp:
        msg = 'Failed to generate Hashes'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def is_reserved_file_conflict(file_path):
    """Check for reserved file conflict."""
    if any(file_path.startswith(i) and file_path != i for i in RESERVED_FILE_NAMES):
        return True
    return False


def unzip(checksum, app_path, ext_path, size_budget=None):
    """Unzip APK.

    Unzip a APK archive while handling encrypted files, reserved file conflicts,
    path traversal (Zip Slip), and permission adjustments. Some of the anti-analysis
    techniques used by malware authors and packers are handled here.

    Args:
        checksum (str): The checksum of the file.
        app_path (str): Path to the ZIP archive.
        ext_path (str): Path to extract the files.
        size_budget (dict): Optional shared counter, ``{'used': int}``.
            When set, this call continues that uncompressed-byte total and
            stops at ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE. The OS unzip fallback
            is not used, so a failed open cannot bypass the cap.

    Returns:
        list: A list of files extracted or an empty list if an error occurs.
    """
    msg = 'Unzipping'
    logger.info(msg)
    append_scan_status(checksum, msg)
    files = []
    original_ext_path = ext_path
    budgeted = size_budget is not None
    # A shared budget must not fall through to OS unzip: that path has no
    # byte cap. Initialize the flag so a failed ZipFile() open still falls
    # through on the default path instead of raising UnboundLocalError.
    stop_fallback_extraction = budgeted
    try:
        with zipfile.ZipFile(app_path, 'r') as zipptr:
            files = zipptr.namelist()
            if budgeted:
                total_size = size_budget.get('used', 0)
            else:
                total_size = 0
                stop_fallback_extraction = False
            for fileinfo in zipptr.infolist():
                ext_path = original_ext_path

                # Skip encrypted files
                if fileinfo.flag_bits & 0x1:
                    msg = ('Skipping encrypted file '
                           f'{sanitize_for_logging(fileinfo.filename)}')
                    logger.warning(msg)
                    continue

                file_path = fileinfo.filename.rstrip('/\\')  # Remove trailing slashes

                # Decode the filename
                if not isinstance(file_path, str):
                    file_path = file_path.decode('utf-8', errors='replace')

                # Check for reserved file conflict
                if is_reserved_file_conflict(file_path):
                    ext_path = str(Path(ext_path) / '_conflict_')

                # Handle Zip Slip
                destination = Path(ext_path) / file_path
                if (is_path_traversal(file_path)
                        or not is_safe_path(
                            ext_path, destination, file_path)):
                    msg = ('Zip slip detected. skipped extracting'
                           f' {sanitize_for_logging(file_path)}')
                    logger.error(msg)
                    stop_fallback_extraction = True
                    continue

                # Check uncompressed size
                if not fileinfo.is_dir():
                    total_size += fileinfo.file_size
                    if budgeted:
                        size_budget['used'] = total_size
                    if fileinfo.file_size > settings.ZIP_MAX_UNCOMPRESSED_FILE_SIZE:
                        size_mb = fileinfo.file_size / (1024 * 1024)
                        msg = (f'File too large ({size_mb:.2f} MB). Skipping '
                               f'{sanitize_for_logging(file_path)}')
                        logger.warning(msg)
                        continue
                    if total_size > settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE:
                        stop_fallback_extraction = True
                        total_size_mb = total_size / (1024 * 1024)
                        msg = ('Total uncompressed size '
                               f'({total_size_mb:.2f} MB) exceeds limit. '
                               'Aborting extraction.')
                        logger.error(msg)
                        raise Exception(msg)

                # Fix permissions
                if fileinfo.is_dir():
                    # Directories should have rwxr-xr-x (755)
                    # Skip creating directories
                    continue
                else:
                    # Files should have rw-r--r-- (644)
                    fileinfo.external_attr = (0o100644 << 16) | (
                        fileinfo.external_attr & 0xFFFF)

                # Extract the file
                try:
                    zipptr.extract(file_path, ext_path)
                except Exception:
                    logger.warning(
                        'Failed to extract %s', sanitize_for_logging(file_path))
    except Exception as exp:
        msg = f'Unzipping Error - {str(exp)}'
        logger.error(msg)
        append_scan_status(checksum, msg, repr(exp))
        # Do not fallback to OS unzip
        # if the total uncompressed file size is too large
        # or if zip slip is detected
        if stop_fallback_extraction:
            return files
        # Fallback to OS unzip
        ofiles = os_unzip(checksum, app_path, ext_path)
        if not files:
            files = ofiles
    return files


_EOCD_SIG = b'PK\x05\x06'
_CD_SIG = b'PK\x01\x02'
_ZIP64_EOCD_SIG = b'PK\x06\x06'
_ZIP64_LOC_SIG = b'PK\x06\x07'
_REGULAR_FILE_MODE = 0o100644


def _read_at(handle, offset, size):
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise ValueError('short read')
    return data


def _eocd_offset(handle, size):
    """Return the end-of-central-directory offset."""
    window = min(size, 65535 + 22)
    data = _read_at(handle, size - window, window)
    rel = data.rfind(_EOCD_SIG)
    if rel < 0 or window - rel < 22:
        raise ValueError('EOCD not found')
    return size - window + rel


def _central_directory_offset(handle, eocd, size):
    """Return the central-directory offset, including ZIP64."""
    cd_offset = struct.unpack('<I', _read_at(handle, eocd + 16, 4))[0]
    if cd_offset != 0xFFFFFFFF:
        return cd_offset
    loc = eocd - 20
    if loc < 0:
        raise ValueError('ZIP64 locator missing')
    locator = _read_at(handle, loc, 20)
    if locator[:4] != _ZIP64_LOC_SIG:
        raise ValueError('ZIP64 locator missing')
    z64 = struct.unpack_from('<Q', locator, 8)[0]
    if z64 + 56 > size:
        raise ValueError('ZIP64 EOCD missing')
    eocd64 = _read_at(handle, z64, 56)
    if eocd64[:4] != _ZIP64_EOCD_SIG:
        raise ValueError('ZIP64 EOCD missing')
    return struct.unpack_from('<Q', eocd64, 48)[0]


def _unix_mode_is_special(mode):
    return (stat.S_ISLNK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)
            or stat.S_ISCHR(mode) or stat.S_ISBLK(mode))


def _rewrite_special_central_directory(handle):
    """Rewrite symlink and device modes to a regular file."""
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    eocd = _eocd_offset(handle, size)
    pos = _central_directory_offset(handle, eocd, size)
    if pos < 0 or pos > size:
        raise ValueError('central directory offset out of range')
    while pos + 46 <= size:
        header = _read_at(handle, pos, 46)
        if header[:4] != _CD_SIG:
            break
        name_len, extra_len, comment_len = struct.unpack_from(
            '<HHH', header, 28)
        next_pos = pos + 46 + name_len + extra_len + comment_len
        if next_pos < pos or next_pos > size:
            raise ValueError('central directory entry exceeds archive')
        external_attr = struct.unpack_from('<I', header, 38)[0]
        mode = (external_attr >> 16) & 0xFFFF
        if _unix_mode_is_special(mode):
            patched_attr = (
                (_REGULAR_FILE_MODE << 16) | (external_attr & 0xFFFF))
            handle.seek(pos + 38)
            handle.write(struct.pack('<I', patched_attr))
        pos = next_pos
    marker = _read_at(handle, pos, 4) if pos + 4 <= size else b''
    if marker not in (_EOCD_SIG, _ZIP64_EOCD_SIG):
        raise ValueError('central directory walk did not finish')


def _patched_zip_dir(dest_parent):
    parent = Path(dest_parent).parent
    try:
        if parent.is_symlink() or not parent.is_dir():
            return None
    except OSError:
        return None
    return parent.as_posix()


def neutralize_zip_special_modes(src, dest_parent):
    """Copy src and rewrite symlink and device modes to a regular file.

    Info-ZIP reads the Unix mode from the central-directory external
    attributes. The copy is streamed, and only those 4-byte fields are
    patched. The uploaded sample is left untouched.
    """
    fd, name = tempfile.mkstemp(
        prefix='mobsf-unzip-',
        suffix='.zip',
        dir=_patched_zip_dir(dest_parent))
    os.close(fd)
    try:
        shutil.copyfile(src, name)
        with open(name, 'r+b') as handle:
            _rewrite_special_central_directory(handle)
    except Exception:
        os.unlink(name)
        raise
    return name


def symlink_points_outside(link, root_real):
    """True when the link target resolves outside root_real."""
    raw = os.readlink(link)
    if os.path.isabs(raw):
        joined = raw
    else:
        joined = os.path.join(os.path.dirname(link), raw)
    try:
        resolved = os.path.realpath(joined)
        return os.path.commonpath((root_real, resolved)) != root_real
    except (OSError, ValueError):
        return True


def remove_external_symlinks(root):
    """Drop links that resolve outside root, plus fifos and device nodes.

    A symlink whose target stays inside root is kept. os.unlink removes the
    link itself and does not delete an external target.
    """
    if os.path.islink(root) or not os.path.isdir(root):
        return
    root_real = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            try:
                if not is_pipe_or_link(path):
                    continue
                mode = os.lstat(path).st_mode
                if (stat.S_ISLNK(mode)
                        and not symlink_points_outside(path, root_real)):
                    continue
                logger.warning(
                    'Removing external link %s', sanitize_for_logging(name))
                os.unlink(path)
            except OSError:
                logger.warning(
                    'Failed to remove %s', sanitize_for_logging(name))


def os_unzip(checksum, app_path, ext_path):
    """Unzip using OS utility."""
    msg = 'Attempting to unzip with OS unzip utility'
    logger.info(msg)
    append_scan_status(checksum, msg)
    patched = None
    try:
        if platform.system() == 'Windows':
            msg = 'Unzipping Error. Not yet implemented in Windows'
            logger.warning(msg)
            append_scan_status(checksum, msg)
            return []
        unzip_b = shutil.which('unzip')
        if not unzip_b:
            msg = 'OS Unzip utility not found'
            logger.warning(msg)
            append_scan_status(checksum, msg)
            return []
        if os.path.islink(ext_path):
            msg = 'Extraction directory is a symlink'
            logger.error(msg)
            append_scan_status(checksum, msg)
            return []
        extract_from = app_path
        try:
            patched = neutralize_zip_special_modes(app_path, ext_path)
            extract_from = patched
        except Exception:
            logger.warning('Could not strip symlink modes before OS unzip')
        # OS unzip strips absolute paths and '..' from member names.
        # Symlink modes are rewritten above so it cannot create a link.
        subprocess.call(
            [unzip_b, '-o', '-q', extract_from, '-d', ext_path])
        # chmod first. A directory mode such as 0500 has no write bit, so
        # unlinking a symlink inside it fails and the link would survive.
        # set_permissions skips links, so this does not chmod the target.
        set_permissions(ext_path)
        remove_external_symlinks(ext_path)
        # Listing is best-effort. A truncated central-directory size makes
        # ZipFile reject the archive, and unzip -l may exit non-zero while
        # still having extracted the members above.
        try:
            dat = subprocess.check_output(
                [unzip_b, '-qq', '-l', app_path],
                stderr=subprocess.DEVNULL)
            listing = dat.decode('utf-8', errors='replace').split('\n')
            return ['Length   Date   Time   Name'] + listing
        except (OSError, subprocess.CalledProcessError):
            logger.warning('Could not list archive entries after OS unzip')
            return []
    except Exception as exp:
        msg = 'Unzipping Error with OS unzip utility'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    finally:
        if patched:
            try:
                os.unlink(patched)
            except OSError:
                logger.warning('Failed to remove temporary unzip copy')
    return []


def lipo_thin(checksum, src, dst):
    """Thin Fat binary."""
    new_src = None
    try:
        msg = 'Thinning Fat binary'
        logger.info(msg)
        append_scan_status(checksum, msg)
        lipo = shutil.which('lipo')
        out = Path(dst) / (Path(src).stem + '_thin.a')
        new_src = out.as_posix()
        archs = [
            'armv7', 'armv6', 'arm64', 'x86_64',
            'armv4t', 'armv5', 'armv6m', 'armv7f',
            'armv7s', 'armv7k', 'armv7m', 'armv7em',
            'arm64v8']
        for arch in archs:
            args = [
                lipo,
                src,
                '-thin',
                arch,
                '-output',
                new_src]
            out = subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT)
            if out.returncode == 0:
                break
    except Exception as exp:
        msg = 'lipo Fat binary thinning failed'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    return new_src


def ar_os(src, dst):
    """Extract AR using OS utility."""
    out = b''
    cur = os.getcwd()
    try:
        os.chdir(dst)
        files = subprocess.check_output(
            [shutil.which('ar'), 't', src],
            stderr=subprocess.STDOUT)
        for raw_file in files.decode('utf-8').split('\n'):
            out = Path(dst) / raw_file
            if (is_path_traversal(raw_file)
                    or not is_safe_path(dst, out, raw_file)):
                msg = f'AR slip detected in AR file {src} at {raw_file}'
                logger.error(msg)
                raise ValueError(msg)
        out = subprocess.check_output(
            [shutil.which('ar'), 'x', src],
            stderr=subprocess.STDOUT)
    except ValueError:
        out = b''
    except Exception as exp:
        out = exp.output
    finally:
        os.chdir(cur)
    return out


def _resolve_ar_entry(raw_name, data, gnu_table):
    """Resolve member name and payload for BSD, GNU, or normal ar headers."""
    if raw_name.startswith(b'#1/'):
        name_len = int(raw_name[3:])
        return data[:name_len].rstrip(b'\x00'), data[name_len:]
    if raw_name.startswith(b'/') and gnu_table is not None:
        offset = int(raw_name[1:])
        sep = b'\x00' if b'\x00' in gnu_table else b'\n'
        end = gnu_table.find(sep, offset)
        if end == -1:
            end = len(gnu_table)
        return gnu_table[offset:end].removesuffix(b'/'), data
    entry_name = raw_name.rstrip(b'/') if len(raw_name) > 1 else raw_name
    return entry_name, data


def _read_ar_member(f):
    """Read one 60-byte ar member header and its payload bytes."""
    header = f.read(60)
    if not header:
        return None, None
    if len(header) < 60:
        raise ValueError('Truncated ar header')
    name, _, _, _, _, size_raw, magic = struct.unpack(
        '16s12s6s6s8s10s2s', header)
    if magic != b'\x60\x0a':
        raise ValueError('Invalid ar header magic')
    size = int(size_raw)
    data = f.read(size)
    if len(data) < size:
        raise ValueError('Truncated ar member')
    if size % 2 == 1:
        f.read(1)
    return name.rstrip(b' '), data


def _iter_ar_archive(src):
    """Yield (name_bytes, data_bytes) from a standard Unix ar archive."""
    with Path(src).open('rb') as f:
        if f.read(8) != b'!<arch>\n':
            raise ValueError('Not a standard Unix ar archive')
        gnu_table = None
        while True:
            raw_name, data = _read_ar_member(f)
            if raw_name is None:
                break
            if raw_name in (b'//', b'/SYM64/'):
                gnu_table = data
            elif raw_name != b'/':
                yield _resolve_ar_entry(raw_name, data, gnu_table)


def ar_extract(checksum, src, dst):
    """Extract AR archive."""
    msg = 'Extracting static library archive'
    logger.info(msg)
    append_scan_status(checksum, msg)
    try:
        for a, val in _iter_ar_archive(src):
            # Handle archive slip attacks
            filtered = a.decode('utf-8', 'ignore')
            if is_path_traversal(filtered):
                msg = f'Zip slip detected. skipped extracting {filtered}'
                logger.warning(msg)
                append_scan_status(checksum, msg)
                continue
            out = Path(dst) / filtered
            if not is_safe_path(dst, out, filtered):
                msg = f'AR slip detected. skipped extracting {filtered}'
                logger.warning(msg)
                append_scan_status(checksum, msg)
                continue
            out.write_bytes(val)
    except Exception:
        # Possibly dealing with Fat binary, needs Mac host
        msg = 'Failed to extract .a archive'
        logger.warning(msg)
        append_scan_status(checksum, msg)
        # Use os ar utility
        plat = platform.system()
        os_err = 'Possibly a Fat binary. Requires MacOS for Analysis'
        if plat == 'Windows':
            logger.warning(os_err)
            append_scan_status(checksum, os_err)
            return
        msg = 'Using OS ar utility to handle archive'
        logger.info(msg)
        append_scan_status(checksum, msg)
        exp = ar_os(src, dst)
        if len(exp) > 3 and plat == 'Linux':
            # Can't convert FAT binary in Linux
            logger.warning(os_err)
            append_scan_status(checksum, os_err)
            return
        if b'lipo(1)' in exp:
            msg = 'Fat binary archive identified'
            logger.info(msg)
            append_scan_status(checksum, msg)
            # Fat binary archive
            try:
                nw_src = lipo_thin(checksum, src, dst)
                if nw_src:
                    ar_os(nw_src, dst)
            except Exception as exp:
                msg = 'Failed to thin fat archive'
                logger.exception(msg)
                append_scan_status(checksum, msg, repr(exp))


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code."""
    urls = set()
    emails = set()
    urllist = []
    url_n_file = []
    email_n_file = []
    # URL Extraction
    urllist = URL_REGEX.findall(dat)
    for url in urllist:
        urls.add(url)
    if urls:
        url_n_file.append({
            'urls': list(urls),
            'path': escape(relative_path)})

    # Email Extraction
    for email in EMAIL_REGEX.findall(dat.lower()):
        if not email.startswith('//'):
            emails.add(email)
    if emails:
        email_n_file.append({
            'emails': list(emails),
            'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file


# This is just the first sanity check that triggers generic_compare
@login_required
def compare_apps(request, hash1: str, hash2: str, api=False):
    if hash1 == hash2:
        error_msg = 'Results with same hash cannot be compared'
        return print_n_send_error_response(request, error_msg, api)
    # Second Validation for REST API
    if not (is_md5(hash1) and is_md5(hash2)):
        error_msg = 'Invalid hashes'
        return print_n_send_error_response(request, error_msg, api)
    logger.info(
        'Starting App compare for %s and %s', hash1, hash2)
    return generic_compare(request, hash1, hash2, api)


def get_avg_cvss(findings):
    # Average CVSS Score
    cvss_scores = []
    avg_cvss = 0
    for finding in findings.values():
        find = finding.get('metadata')
        if not find:
            # Hack to support iOS Binary Scan Results
            find = finding
        if find.get('cvss'):
            if find['cvss'] != 0:
                cvss_scores.append(find['cvss'])
    if cvss_scores:
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1)
    if not getattr(settings, 'CVSS_SCORE_ENABLED', False):
        avg_cvss = None
    return avg_cvss


def find_java_source_folder(base_folder: Path):
    # Find the correct java/kotlin source folder for APK/source zip
    # Returns a Tuple of - (SRC_PATH, SRC_TYPE, SRC_SYNTAX)
    return next(p for p in [(base_folder / 'java_source',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'java',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'kotlin',
                             'kotlin', '*.kt'),
                            (base_folder / 'src',
                             'java', '*.java')]
                if p[0].exists())


def is_secret_key(key):
    """Check if the key in the key/value pair is interesting."""
    key_lower = key.lower()
    # Key ends with these strings
    endswith = (
        'api', 'key', 'secret', 'token', 'username',
        'user_name', 'user', 'pass', 'password',
        'private_key', 'access_key',
    )
    # Key contains these strings
    contains = (
        'api_', 'key_', 'aws', 's3_', '_s3', 'secret_',
        'bearer', 'jwt', 'certificate"', 'credential',
        'azure', 'webhook', 'twilio_', 'bitcoin',
        '_auth', 'firebase', 'oauth', 'authorization',
        'private', 'pwd', 'session', 'token_', 'gcp',
    )
    # Key must not contain these strings
    not_string = (
        'label_', 'text', 'hint', 'msg_', 'create_',
        'message', 'new', 'confirm', 'activity_',
        'forgot', 'dashboard_', 'current_', 'signup',
        'sign_in', 'signin', 'title_', 'welcome_',
        'change_', 'this_', 'the_', 'placeholder',
        'invalid_', 'btn_', 'action_', 'prompt_',
        'lable', 'hide_', 'old', 'update', 'error',
        'empty', 'txt_', 'lbl_',
    )
    not_contains_str = any(i in key_lower for i in not_string)
    contains_str = any(i in key_lower for i in contains)
    endswith_str = any(key_lower.endswith(i) for i in endswith)
    return (endswith_str or contains_str) and not not_contains_str


def strings_and_entropies(checksum, src, exts):
    """Get Strings and Entropies."""
    msg = 'Extracting String values and entropies from Code'
    logger.info(msg)
    append_scan_status(checksum, msg)
    data = {
        'strings': set(),
        'secrets': set(),
    }
    try:
        if not (src and src.exists()):
            return data
        excludes = ('\\u0', 'com.google.')
        eslash = ('Ljava', 'Lkotlin', 'kotlin', 'android')
        for p in src.rglob('*'):
            if p.suffix not in exts or not p.exists():
                continue
            matches = STRINGS_REGEX.finditer(
                p.read_text(encoding='utf-8', errors='ignore'),
                re.MULTILINE)
            for match in matches:
                string = match.group()
                if len(string) < 4:
                    continue
                if any(i in string for i in excludes):
                    continue
                if any(i in string and '/' in string for i in eslash):
                    continue
                if not string[0].isalnum():
                    continue
                data['strings'].add(string)
        if data['strings']:
            data['secrets'] = get_secrets(data['strings'])
    except Exception as exp:
        msg = 'Failed to extract String values and entropies from Code'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return data


def get_symbols(symbols):
    all_symbols = []
    for i in symbols:
        for _, val in i.items():
            all_symbols.extend(val)
    return list(set(all_symbols))


@login_required
@permission_required(Permissions.SCAN)
def scan_library(request, checksum):
    """Scan a shared library or framework from path name."""
    try:
        libchecksum = None
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                'Invalid MD5')
        relative_path = request.GET['library']
        lib_dir = Path(settings.UPLD_DIR) / checksum

        sfile = lib_dir / relative_path
        if (is_path_traversal(relative_path)
                or not is_safe_path(
                    lib_dir.as_posix(), sfile.as_posix(), relative_path)):
            msg = 'Path Traversal Detected!'
            return print_n_send_error_response(request, msg)
        ext = sfile.suffix
        if not ext and 'Frameworks' in relative_path:
            # Force Dylib on Frameworks
            ext = '.dylib'
        if (not sfile.exists()
                or not sfile.is_file()
                or is_pipe_or_link(sfile)):
            msg = 'Library File not found'
            return print_n_send_error_response(request, msg)
        with open(sfile, 'rb') as f:
            libchecksum = handle_uploaded_file(f, ext)
        if ext in [f'.{i}' for i in settings.IOS_EXTS]:
            static_analyzer = 'static_analyzer_ios'
        elif ext == '.appx':
            # Not applicable, but still set it
            static_analyzer = 'windows_static_analyzer'
        elif ext in [f'.{i}' for i in settings.ANDROID_EXTS]:
            static_analyzer = 'static_analyzer'
        else:
            msg = 'Extension not supported'
            return print_n_send_error_response(request, msg)
        data = {
            'analyzer': static_analyzer,
            'status': 'success',
            'hash': libchecksum,
            'scan_type': ext.replace('.', ''),
            'file_name': sfile.name,
        }
        add_to_recent_scan(data)
        return HttpResponseRedirect(f'/{static_analyzer}/{libchecksum}/')
    except Exception:
        msg = 'Failed to perform Static Analysis of library'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)
