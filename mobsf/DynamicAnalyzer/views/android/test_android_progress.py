# -*- coding: utf_8 -*-
"""Tests for Android dynamic analysis progress capture."""
import logging
import threading
import unittest

from mobsf.DynamicAnalyzer.views.android.progress import (
    pop_progress_sink,
    push_progress_sink,
)


class AndroidProgressTests(unittest.TestCase):
    """Console INFO lines are captured only on the setup thread."""

    def setUp(self):
        self.logger = logging.getLogger('mobsf.DynamicAnalyzer')
        self.level = self.logger.level
        self.logger.setLevel(logging.INFO)
        self.logs = []
        self.token = push_progress_sink(self.logs.append)

    def tearDown(self):
        pop_progress_sink(self.token)
        self.logger.setLevel(self.level)

    def test_info_logs_follow_the_console_steps(self):
        child = logging.getLogger(
            'mobsf.DynamicAnalyzer.views.android.environment')
        child.info('Starting HTTPS Proxy on %s', 1337)
        child.info('Starting HTTPS Proxy on %s', 1337)
        child.info('Installing APK - %s', 'com.example.app')
        child.debug('not shown')
        logging.getLogger('mobsf.MobSF').info('unrelated')
        self.assertEqual(self.logs, [
            'Starting HTTPS Proxy on 1337',
            'Installing APK - com.example.app',
        ])

    def test_other_threads_are_not_captured(self):
        def worker():
            logging.getLogger(
                'mobsf.DynamicAnalyzer.tools.apk_patcher',
            ).info('Signing the Frida Gadget APK')

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        self.logger.info('Preparing Android dynamic analysis')
        self.assertEqual(
            self.logs,
            ['Preparing Android dynamic analysis'],
        )

    def test_messages_are_single_line_and_bounded(self):
        self.logger.info('Signing\r\nAPK\x00now')
        self.logger.info('x' * 400)
        self.assertEqual(self.logs[0], 'Signing APK now')
        self.assertLessEqual(len(self.logs[1]), 180)
        self.assertTrue(self.logs[1].endswith('…'))

    def test_capture_stops_when_the_request_finishes(self):
        self.logger.info('Remounting')
        pop_progress_sink(self.token)
        self.token = None
        self.logger.info('after the request')
        self.assertEqual(self.logs, ['Remounting'])
