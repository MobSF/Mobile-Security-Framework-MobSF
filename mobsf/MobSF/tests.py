"""MobSF core unit tests."""
import os
from unittest import mock

from django.test import SimpleTestCase

from mobsf.MobSF.env import env_flag


class EnvFlagTests(SimpleTestCase):

    def test_disabled_values(self):
        for val in ('', ' ', '0', '"0"', "'0'", '""', 'false', 'False',
                    'FALSE', 'no', 'off', ' 0 '):
            with mock.patch.dict(os.environ, {'MOBSF_TEST_FLAG': val}):
                self.assertFalse(env_flag('MOBSF_TEST_FLAG'), repr(val))

    def test_enabled_values(self):
        for val in ('1', '"1"', 'true', 'True', 'yes', 'on'):
            with mock.patch.dict(os.environ, {'MOBSF_TEST_FLAG': val}):
                self.assertTrue(env_flag('MOBSF_TEST_FLAG'), repr(val))

    def test_unset(self):
        with mock.patch.dict(os.environ, clear=True):
            self.assertFalse(env_flag('MOBSF_TEST_FLAG'))
