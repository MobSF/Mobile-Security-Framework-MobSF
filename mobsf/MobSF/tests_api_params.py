# -*- coding: utf_8 -*-
"""Tests for REST API POST parameter validation."""
import json

from django.test import RequestFactory, SimpleTestCase

from mobsf.MobSF.views.api import api_ios_device_analysis as ios_device

URL = '/api/v1/ios/device/'


class ApiMissingParameterTests(SimpleTestCase):
    """Missing POST parameters must be a 422, never a 500 traceback."""

    def setUp(self):
        self.factory = RequestFactory()

    def _post(self, view, data):
        return view(self.factory.post(URL, data))

    def test_download_app_data_missing_bundle_id(self):
        # An unrelated extra field must not hide the missing parameter.
        resp = self._post(
            ios_device.api_device_download_app_data,
            {'device_id': 'device-1', 'note': 'unrelated'})
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(
            json.loads(resp.content), {'error': 'Missing Parameters'})

    def test_report_json_missing_bundle_id(self):
        resp = self._post(
            ios_device.api_device_report_json,
            {'device_id': 'device-1', 'note': 'unrelated'})
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(
            json.loads(resp.content), {'error': 'Missing Parameters'})

    def test_install_ipa_missing_checksum(self):
        resp = self._post(
            ios_device.api_device_install_ipa,
            {'device_id': 'device-1', 'note': 'unrelated'})
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(
            json.loads(resp.content), {'error': 'Missing Parameters'})

    def test_extra_field_with_all_parameters_is_not_rejected(self):
        # The presence check must not start rejecting valid supersets.
        resp = self._post(
            ios_device.api_device_download_app_data,
            {'device_id': 'device-1',
             'bundle_id': 'com.example.app',
             'note': 'unrelated'})
        self.assertNotEqual(resp.status_code, 422)
