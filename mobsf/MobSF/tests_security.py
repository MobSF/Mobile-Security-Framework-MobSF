"""Unit tests for mobsf.MobSF.security."""
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from mobsf.MobSF import security
from mobsf.MobSF.security import (
    clean_filename,
    cmd_injection_check,
    is_attack_pattern,
    is_disallowed_ip,
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
    is_safe_windows_batch_arg,
    safe_request,
    safe_stream_request,
    sanitize_filename,
    sanitize_for_logging,
    sanitize_redirect,
    subprocess_hook,
)
from mobsf.MobSF.utils import sha256


class SanitizeRedirectTests(SimpleTestCase):

    def test_relative_paths_allowed(self):
        self.assertEqual(sanitize_redirect('/home'), '/home')
        self.assertEqual(
            sanitize_redirect('/static_analyzer/?name=a'),
            '/static_analyzer/?name=a')

    def test_open_redirect_variants_blocked(self):
        for url in ('//evil.com', '/\\evil.com', '/\t/evil.com',
                    '/\n/evil.com', '/\r/evil.com', 'https://evil.com',
                    '\\\\evil.com', 'evil.com', ' //evil.com',
                    'javascript:alert(1)', '', None):
            with self.subTest(url=url):
                self.assertEqual(sanitize_redirect(url), '/')


class PathTraversalTests(SimpleTestCase):

    def test_traversal_detected(self):
        for path in ('../etc/passwd', 'a/../../b', '..\\windows',
                     '/etc/passwd', '\\\\server\\share\\x', 'C:\\x',
                     'C:foo', '%2e%2e/x', '%252e%252e/x', 'a\x00b',
                     '\uff0e\uff0e\uff0fx', '\uff0e\uff0e\uff3cx',
                     '\uff05\uff12\uff45\uff05\uff12\uff45/x'):
            with self.subTest(path=path):
                self.assertTrue(is_path_traversal(path))

    @mock.patch.object(security, 'IS_WINDOWS', False)
    def test_safe_paths(self):
        for path in ('res/drawable/icon.png', 'com/example/con/Foo.java',
                     'AndroidManifest.xml', 'a/./b.txt', '', None):
            with self.subTest(path=path):
                self.assertFalse(is_path_traversal(path))

    @mock.patch.object(security, 'IS_WINDOWS', True)
    def test_windows_only_checks(self):
        for path in ('file.txt:stream', 'CON', 'nul.txt', 'a/COM1.log',
                     'LPT9', 'conin$', 'a/aux', 'COM\u00b9', 'foo.',
                     'foo ', 'dir./x.txt'):
            with self.subTest(path=path):
                self.assertTrue(is_path_traversal(path))
        for path in ('console.txt', 'a/b.txt', 'com/example/Foo.java'):
            with self.subTest(path=path):
                self.assertFalse(is_path_traversal(path))


class SafePathTests(SimpleTestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'root'
        self.root.mkdir()
        self.outside = Path(self.tmp.name) / 'outside'
        self.outside.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_contained_path(self):
        self.assertTrue(
            is_safe_path(self.root, self.root / 'a.txt', 'a.txt'))

    def test_traversal_rejected(self):
        self.assertFalse(
            is_safe_path(self.root, self.root / '..' / 'x', '../x'))

    def test_symlink_escape_rejected(self):
        link = self.root / 'link'
        try:
            os.symlink(self.outside, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks not supported')
        self.assertFalse(
            is_safe_path(self.root, link / 'x.txt', 'link/x.txt'))

    def test_different_drives_rejected(self):
        with mock.patch.object(
                security.os.path, 'commonpath', side_effect=ValueError):
            self.assertFalse(
                is_safe_path(self.root, self.root / 'a.txt', 'a.txt'))


class DisallowedIPTests(SimpleTestCase):

    def test_disallowed(self):
        for ip in ('127.0.0.1', '10.0.0.1', '169.254.169.254',
                   '100.64.0.1', '192.168.1.1', '0.0.0.0', '::1',
                   '::ffff:127.0.0.1', '2002:7f00:1::',
                   '2001:0:4136:e378:8000:63bf:80ff:fffe',
                   '64:ff9b::7f00:1', 'fc00::1', 'not-an-ip',
                   '168.63.129.16', '::ffff:168.63.129.16'):
            with self.subTest(ip=ip):
                self.assertTrue(is_disallowed_ip(ip))

    def test_public(self):
        for ip in ('8.8.8.8', '2606:4700:4700::1111'):
            with self.subTest(ip=ip):
                self.assertFalse(is_disallowed_ip(ip))

    def test_validated_host_ports(self):
        self.assertIsNone(security._validated_host('example.com:0'))
        self.assertIsNone(security._validated_host('example.com:8080'))
        self.assertIsNotNone(security._validated_host('example.com'))
        self.assertIsNotNone(security._validated_host('example.com:443'))


class SafeStreamRequestTests(SimpleTestCase):

    @staticmethod
    def _response(status, location=None):
        response = mock.Mock(status_code=status)
        response.headers = {'Location': location} if location else {}
        return mock.Mock(), response

    def test_cross_host_redirect_strips_credentials(self):
        responses = [
            self._response(302, 'https://other.example/x'),
            self._response(200),
        ]
        with mock.patch.object(
                security, '_open_pinned_request',
                side_effect=responses) as opener:
            with safe_stream_request(
                    'GET', 'https://a.example/',
                    max_redirects=1,
                    headers={'Authorization': 'x', 'User-Agent': 'y'}):
                pass
        first, second = opener.call_args_list
        self.assertEqual(first.kwargs['timeout'],
                         security.DEFAULT_REQUEST_TIMEOUT)
        self.assertIn('Authorization', first.kwargs['headers'])
        self.assertEqual(second.args[1], 'https://other.example/x')
        self.assertEqual(second.kwargs['headers'], {'User-Agent': 'y'})

    def test_same_host_redirect_keeps_headers(self):
        responses = [
            self._response(302, '/next'),
            self._response(200),
        ]
        with mock.patch.object(
                security, '_open_pinned_request',
                side_effect=responses) as opener:
            with safe_stream_request(
                    'GET', 'https://a.example/', max_redirects=1,
                    headers={'Authorization': 'x'}, timeout=5):
                pass
        second = opener.call_args_list[1]
        self.assertEqual(second.kwargs['headers'], {'Authorization': 'x'})
        self.assertEqual(second.kwargs['timeout'], 5)

    def test_https_to_http_redirect_blocked(self):
        with mock.patch.object(
                security, '_open_pinned_request',
                side_effect=[self._response(302, 'http://a.example/')]):
            with self.assertRaises(ValueError):
                with safe_stream_request(
                        'GET', 'https://a.example/', max_redirects=1):
                    pass

    def test_303_switches_to_get(self):
        responses = [
            self._response(303, '/done'),
            self._response(200),
        ]
        with mock.patch.object(
                security, '_open_pinned_request',
                side_effect=responses) as opener:
            with safe_stream_request(
                    'POST', 'https://a.example/', max_redirects=1,
                    data={'a': 'b'}):
                pass
        second = opener.call_args_list[1]
        self.assertEqual(second.args[0], 'GET')
        self.assertNotIn('data', second.kwargs)


class SafeRequestLimitTests(SimpleTestCase):

    @staticmethod
    def _opener(chunks):
        response = mock.Mock(status_code=200, headers={})
        response.raw.stream.return_value = iter(chunks)
        return mock.patch.object(
            security, '_open_pinned_request',
            return_value=(mock.Mock(), response))

    def test_body_returned(self):
        with self._opener([b'ab', b'cd']):
            response = safe_request('GET', 'https://a.example/')
        self.assertEqual(response._content, b'abcd')

    def test_size_limit(self):
        with self._opener([b'a' * 6, b'a' * 6]):
            with self.assertRaises(ValueError):
                safe_request('GET', 'https://a.example/',
                             max_response_size=10)

    def test_total_time_limit(self):
        # Each chunk arrives within the socket timeout, but the
        # body as a whole runs past max_total_time.
        clock = iter([0, 4, 8, 12])
        with self._opener([b'a', b'b', b'c']), mock.patch.object(
                security.time, 'monotonic', side_effect=lambda: next(clock)):
            with self.assertRaises(TimeoutError):
                safe_request('GET', 'https://a.example/',
                             max_total_time=10)


class SubprocessHookTests(SimpleTestCase):

    def setUp(self):
        self.oldfunc = mock.Mock(return_value='ran')
        self.python_key = security._hash_key(sys.executable)
        self.known_map = {
            self.python_key: sha256(sys.executable),
            'signature': 'unused',
        }

    def test_no_hash_map_passes_through(self):
        with mock.patch.object(security, 'EXECUTABLE_HASH_MAP', None):
            self.assertEqual(
                subprocess_hook(self.oldfunc, [sys.executable, '-V']), 'ran')

    def test_missing_executable_passes_through(self):
        with mock.patch.object(
                security, 'EXECUTABLE_HASH_MAP', self.known_map):
            subprocess_hook(self.oldfunc, ['mobsf-no-such-binary-xyz'])
        self.oldfunc.assert_called_once()

    def test_args_keyword_and_pathlike(self):
        with mock.patch.object(
                security, 'EXECUTABLE_HASH_MAP', self.known_map):
            subprocess_hook(self.oldfunc, args=[sys.executable, '-V'])
            subprocess_hook(
                self.oldfunc, [Path(sys.executable), Path('tool.JAR')])
            subprocess_hook(self.oldfunc, Path(sys.executable))
        self.assertEqual(self.oldfunc.call_count, 3)

    def test_tampered_executable_detected(self):
        tampered = {self.python_key: '0' * 64, 'signature': 'unused'}
        with mock.patch.object(security, 'EXECUTABLE_HASH_MAP', tampered):
            with self.assertRaisesRegex(Exception, 'Tampering Detected'):
                subprocess_hook(self.oldfunc, [sys.executable, '-V'])
        self.oldfunc.assert_not_called()

    @mock.patch.object(security, 'IS_WINDOWS', True)
    @mock.patch.object(security, 'EXECUTABLE_HASH_MAP', None)
    def test_windows_batch_arguments(self):
        bat = 'C:/tools/jadx/bin/jadx.BAT'
        subprocess_hook(
            self.oldfunc, [bat, '-d', 'C:/Program Files (x86)/out'])
        self.oldfunc.assert_called_once()
        for arg in ('a&calc', '%PATH%', 'a^b', 'a"b', 'a|b'):
            with self.subTest(arg=arg):
                with self.assertRaises(ValueError):
                    subprocess_hook(self.oldfunc, [bat, arg])

    def test_split_command(self):
        self.assertEqual(
            security._split_command(('ls -la',), {}), ['ls', '-la'])
        with mock.patch.object(security, 'IS_WINDOWS', True):
            self.assertEqual(
                security._split_command(
                    ('"C:\\Program Files\\x.exe" -a',), {}),
                ['C:\\Program Files\\x.exe', '-a'])


class FilenameTests(SimpleTestCase):

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename('my app.apk'), 'my_app.apk')
        self.assertEqual(sanitize_filename('../../x.apk'), 'x.apk')
        self.assertEqual(sanitize_filename('.htaccess'), 'htaccess')
        for name in ('', '.', '..', '___', '/'):
            with self.subTest(name=name):
                self.assertEqual(sanitize_filename(name), 'file')

    def test_sanitize_for_logging(self):
        self.assertEqual(sanitize_for_logging('a\nb\rc\td'), 'a_b_c_d')
        self.assertEqual(sanitize_for_logging(None), 'None')
        self.assertEqual(len(sanitize_for_logging('a' * 500)), 255)

    def test_clean_filename_windows(self):
        with mock.patch.object(security, 'system', return_value='Windows'):
            self.assertEqual(clean_filename('my file.apk'), 'my_file.apk')
            self.assertEqual(clean_filename('CON'), '_CON')
            self.assertEqual(clean_filename('nul.txt'), '_nul.txt')
            self.assertEqual(clean_filename('a.txt..'), 'a.txt')
            self.assertEqual(clean_filename('a.txt. ', replace=''), 'a.txt')
            self.assertEqual(clean_filename('***'), '_')

    def test_clean_filename_posix(self):
        with mock.patch.object(security, 'system', return_value='Linux'):
            self.assertEqual(clean_filename('CON'), 'CON')


class CommandInjectionTests(SimpleTestCase):

    def test_cmd_injection_check(self):
        for value in ('emulator-5554', '192.168.56.101:5555',
                      'com.example.app'):
            with self.subTest(value=value):
                self.assertFalse(cmd_injection_check(value))
        for value in ('a;b', 'a&b', 'a|b', 'a`id`', '$(id)', 'a\nb',
                      'a%0Ab', 'a%3bb', 'a>b', 'a<b'):
            with self.subTest(value=value):
                self.assertTrue(cmd_injection_check(value))

    def test_is_attack_pattern(self):
        self.assertIs(
            is_attack_pattern('api_monitor,ssl_pinning_bypass'), False)
        self.assertIs(is_attack_pattern('com.example.Foo$Bar'), False)
        for value in ('a;b', 'a|b', 'a&&b', '$(id)', '`id`', 'a\nb'):
            with self.subTest(value=value):
                self.assertIs(is_attack_pattern(value), True)

    def test_windows_batch_arg(self):
        self.assertTrue(
            is_safe_windows_batch_arg('C:/Program Files (x86)/a.apk'))
        for arg in ('a&b', '%PATH%', 'a^b', 'a"b', 'a!b', 'a\nb'):
            with self.subTest(arg=arg):
                self.assertFalse(is_safe_windows_batch_arg(arg))


class PipeOrLinkTests(SimpleTestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_regular_file_and_dir(self):
        regular = self.root / 'a.txt'
        regular.write_text('x')
        self.assertFalse(is_pipe_or_link(regular))
        self.assertFalse(is_pipe_or_link(self.root))
        self.assertFalse(is_pipe_or_link(self.root / 'missing'))

    def test_symlink(self):
        target = self.root / 'a.txt'
        target.write_text('x')
        link = self.root / 'link'
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks not supported')
        self.assertTrue(is_pipe_or_link(link))

    def test_fifo(self):
        if not hasattr(os, 'mkfifo'):
            self.skipTest('FIFOs not supported')
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        self.assertTrue(is_pipe_or_link(fifo))

    def test_device_file(self):
        if os.name == 'nt' or not os.path.exists('/dev/null'):
            self.skipTest('No /dev/null')
        self.assertTrue(is_pipe_or_link('/dev/null'))
