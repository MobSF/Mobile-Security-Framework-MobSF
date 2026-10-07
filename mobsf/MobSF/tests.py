# -*- coding: utf_8 -*-
"""Offline regression tests for the centralized security helpers.

These tests lock in the behavior of the validation functions in
``mobsf.MobSF.security`` that protect archive extraction, file paths,
redirects, logging, shell arguments, and outbound host validation
(path traversal, Windows root-relative escapes, SSRF and command
injection). They are deliberately network and database free so they
can run anywhere without samples, a device or internet access.
"""
import os
import shutil
import tempfile

from django.test import SimpleTestCase

from mobsf.MobSF.security import (
    _validated_host,
    cmd_injection_check,
    is_attack_pattern,
    is_disallowed_ip,
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
    sanitize_filename,
    sanitize_for_logging,
    sanitize_redirect,
)


class PathTraversalTests(SimpleTestCase):

    def test_detects_traversal_absolute_and_encoded_paths(self):
        malicious = [
            '../etc/passwd',
            '..',
            'foo/../../bar',
            '/etc/passwd',
            '\\etc',
            'C:\\Windows',
            '\\\\server\\share',
            '%2e%2e%2fx',
            '%252e%252e%252fx',
            'foo\x00bar',
            b'../x',
            123,
        ]
        for case in malicious:
            with self.subTest(case=case):
                self.assertTrue(is_path_traversal(case))

    def test_allows_safe_relative_paths(self):
        safe = [
            '',
            'AndroidManifest.xml',
            'classes.dex',
            'res/drawable-hdpi/icon.png',
            'lib/arm64-v8a/libfoo.so',
        ]
        for case in safe:
            with self.subTest(case=case):
                self.assertFalse(is_path_traversal(case))

    def test_plain_newline_is_not_a_path_traversal(self):
        # Newlines are a log-injection concern handled by
        # sanitize_for_logging, not a path traversal sequence.
        self.assertFalse(is_path_traversal('a\nb'))


class SafePathTests(SimpleTestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, 'sub'))

    def tearDown(self):
        self.tmp.cleanup()

    def test_member_inside_root_is_safe(self):
        target = os.path.join(self.root, 'sub', 'f.txt')
        self.assertTrue(
            is_safe_path(self.root, target, os.path.join('sub', 'f.txt')))

    def test_parent_directory_escape_is_unsafe(self):
        target = os.path.join(self.root, '..', 'outside_file')
        self.assertFalse(
            is_safe_path(
                self.root,
                target,
                os.path.join('..', 'outside_file')))

    def test_traversal_raw_input_is_rejected_even_with_real_target(self):
        inside = os.path.join(self.root, 'sub', 'f.txt')
        self.assertFalse(is_safe_path(self.root, inside, '../x'))

    def test_symlink_pointing_outside_root_is_unsafe(self):
        outside = tempfile.mkdtemp()
        try:
            link = os.path.join(self.root, 'evil_link')
            os.symlink(outside, link)
            target = os.path.join(link, 'file.txt')
            self.assertFalse(
                is_safe_path(
                    self.root,
                    target,
                    os.path.join('evil_link', 'file.txt')))
        finally:
            shutil.rmtree(outside, ignore_errors=True)


class FilenameAndRedirectSanitizationTests(SimpleTestCase):

    def test_sanitize_filename_strips_path_and_special_characters(self):
        cases = {
            'My-App_v1.2.apk': 'My-App_v1.2.apk',
            'a/b\\c*d.png': 'a_b_c_d.png',
            '../../etc/passwd': '.._.._etc_passwd',
            'foo***bar': 'foo_bar',
            'a\r\nb': 'a_b',
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                result = sanitize_filename(raw)
                self.assertEqual(result, expected)
                self.assertNotIn('/', result)
                self.assertNotIn('\\', result)

    def test_sanitize_for_logging_removes_control_characters(self):
        result = sanitize_for_logging('x\ny\r\nz\tw')
        self.assertEqual(result, 'x_y__z_w')
        for char in ('\n', '\r', '\t'):
            self.assertNotIn(char, result)

    def test_sanitize_for_logging_truncates(self):
        self.assertEqual(len(sanitize_for_logging('a' * 300)), 255)
        self.assertEqual(
            len(sanitize_for_logging('a' * 300, max_length=10)),
            10)

    def test_sanitize_redirect_only_allows_relative_paths(self):
        self.assertEqual(sanitize_redirect('/dashboard/'), '/dashboard/')
        for open_redirect in (
            '//evil.com/x',
            'https://evil.com/x',
            'relative',
            '',
        ):
            with self.subTest(case=open_redirect):
                self.assertEqual(sanitize_redirect(open_redirect), '/')


class SSRFIPClassificationTests(SimpleTestCase):

    def test_loopback_private_linklocal_and_metadata_are_blocked(self):
        blocked = [
            '127.0.0.1',
            '127.1.2.3',
            '10.0.0.1',
            '192.168.1.1',
            '172.16.0.1',
            '172.31.255.255',
            '169.254.169.254',  # Cloud metadata endpoint
            '100.64.0.1',       # RFC 6598 carrier-grade NAT
            '0.0.0.0',
            '224.0.0.1',
        ]
        for ip in blocked:
            with self.subTest(ip=ip):
                self.assertTrue(is_disallowed_ip(ip))

    def test_public_ipv4_is_allowed(self):
        allowed = [
            '8.8.8.8',
            '1.1.1.1',
            '172.32.0.1',       # Just outside 172.16.0.0/12
            '100.63.255.255',   # Just outside 100.64.0.0/10
        ]
        for ip in allowed:
            with self.subTest(ip=ip):
                self.assertFalse(is_disallowed_ip(ip))

    def test_internal_ipv6_is_blocked(self):
        for ip in ('::1', '::', 'fc00::1', 'fe80::1'):
            with self.subTest(ip=ip):
                self.assertTrue(is_disallowed_ip(ip))

    def test_public_ipv6_is_allowed(self):
        self.assertFalse(is_disallowed_ip('2606:4700:4700::1111'))

    def test_ipv4_mapped_ipv6_is_unwrapped_before_classification(self):
        self.assertTrue(is_disallowed_ip('::ffff:127.0.0.1'))
        self.assertFalse(is_disallowed_ip('::ffff:8.8.8.8'))

    def test_tunneled_internal_ipv4_is_blocked(self):
        # 6to4 (2002::/16) and NAT64 (64:ff9b::/96) can carry an
        # internal IPv4 destination inside a public-looking IPv6 literal.
        self.assertTrue(is_disallowed_ip('2002:7f00:1::'))
        self.assertTrue(is_disallowed_ip('64:ff9b::7f00:1'))

    def test_unparseable_address_fails_closed(self):
        self.assertTrue(is_disallowed_ip('not-an-ip'))


class ValidatedHostTests(SimpleTestCase):

    def test_accepts_bare_host_and_default_ports(self):
        for host in (
            'example.com',
            'https://example.com',
            'http://example.com',
            'example.com:443',
            'example.com:80',
        ):
            with self.subTest(host=host):
                self.assertIsNotNone(_validated_host(host))

    def test_rejects_path_query_fragment_userinfo_and_custom_ports(self):
        for host in (
            'https://example.com/path',
            'https://example.com?q=1',
            'https://example.com#f',
            'https://user@example.com',
            'https://example.com:8080',
            'ftp://example.com',
        ):
            with self.subTest(host=host):
                self.assertIsNone(_validated_host(host))

    def test_rejects_empty_non_string_and_oversized_hosts(self):
        for host in ('', 123, 'h' * 2100):
            with self.subTest(host=repr(host)):
                self.assertIsNone(_validated_host(host))


class CommandInjectionTests(SimpleTestCase):

    def test_detects_shell_breakers(self):
        malicious = [
            'ls; id',
            'a&&b',
            'a||b',
            'a|b',
            'x%3By',
            '%0aid',
            'a%26%26b',
        ]
        for case in malicious:
            with self.subTest(case=case):
                self.assertTrue(cmd_injection_check(case))

    def test_allows_benign_identifiers(self):
        benign = [
            'com.example.app',
            'frida-server',
            'my app',
            'file_name-1.2',
        ]
        for case in benign:
            with self.subTest(case=case):
                self.assertFalse(cmd_injection_check(case))

    def test_attack_pattern_matches_shell_metacharacters(self):
        for case in ('; id', '$(whoami)', 'a||b', 'a&&b'):
            with self.subTest(case=case):
                self.assertTrue(is_attack_pattern(case))

    def test_attack_pattern_clean_input_returns_no_matches(self):
        for case in ('plain text', 'com.example'):
            with self.subTest(case=case):
                self.assertEqual(is_attack_pattern(case), [])


class PipeOrLinkTests(SimpleTestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_regular_file_is_not_pipe_or_link(self):
        regular = os.path.join(self.root, 'regular.txt')
        with open(regular, 'w') as handle:
            handle.write('x')
        self.assertFalse(is_pipe_or_link(regular))

    def test_symlink_is_detected(self):
        regular = os.path.join(self.root, 'regular.txt')
        with open(regular, 'w') as handle:
            handle.write('x')
        link = os.path.join(self.root, 'alink')
        os.symlink(regular, link)
        self.assertTrue(is_pipe_or_link(link))

    def test_named_pipe_is_detected(self):
        fifo = os.path.join(self.root, 'afifo')
        os.mkfifo(fifo)
        self.assertTrue(is_pipe_or_link(fifo))
