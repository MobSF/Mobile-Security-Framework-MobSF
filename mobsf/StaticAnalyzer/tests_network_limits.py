"""Limits on outbound requests driven by scanned app content."""
import threading
import time
from unittest import mock
from xml.dom import minidom

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.android import manifest_analysis
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    ASSETLINKS_MAX_URLS,
    assetlinks_check,
    get_browsable_activities,
    new_assetlinks_budget,
)
from mobsf.StaticAnalyzer.views.common import firebase


def well_knowns(count, prefix='h'):
    return {
        f'https://{prefix}{i}.example.com/.well-known/assetlinks.json':
            f'https://{prefix}{i}.example.com'
        for i in range(count)}


def ok_result(host, w_url, deadline=None):
    return {'url': w_url, 'host': host, 'status_code': 404, 'status': False}


class AssetlinksLimitTests(SimpleTestCase):

    def test_host_cap_shared_across_activities(self):
        budget = new_assetlinks_budget()
        with mock.patch.object(
                manifest_analysis, '_check_url',
                side_effect=ok_result) as check:
            first = assetlinks_check('A', well_knowns(15, 'a'), budget)
            second = assetlinks_check('B', well_knowns(15, 'b'), budget)
        self.assertEqual(len(first), 15)
        self.assertEqual(len(second), ASSETLINKS_MAX_URLS - 15)
        self.assertEqual(check.call_count, ASSETLINKS_MAX_URLS)

    def test_repeated_url_fetched_once(self):
        budget = new_assetlinks_budget()
        urls = well_knowns(2)
        with mock.patch.object(
                manifest_analysis, '_check_url',
                side_effect=ok_result) as check:
            assetlinks_check('A', urls, budget)
            again = assetlinks_check('B', urls, budget)
        self.assertEqual(check.call_count, 2)
        self.assertEqual(len(again), 2)

    def test_total_time_limit(self):
        release = threading.Event()

        def stalled(host, w_url, deadline=None):
            release.wait(10)
            return ok_result(host, w_url)

        budget = new_assetlinks_budget()
        budget['deadline'] = time.monotonic() + 0.2
        start = time.monotonic()
        try:
            with mock.patch.object(
                    manifest_analysis, '_check_url', side_effect=stalled):
                findings = assetlinks_check('A', well_knowns(2), budget)
        finally:
            release.set()
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(
            f['status'] is False and f['status_code'] is None
            for f in findings))

    def test_expired_budget_starts_no_requests(self):
        budget = new_assetlinks_budget()
        budget['deadline'] = time.monotonic() - 1
        with mock.patch.object(manifest_analysis, '_check_url') as check:
            findings = assetlinks_check('A', well_knowns(3), budget)
        check.assert_not_called()
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f['status_code'] is None for f in findings))

    def test_dns_runs_only_for_capped_urls(self):
        hosts = ''.join(
            f'<data android:scheme="https" android:host="h{i}.example.com"/>'
            for i in range(ASSETLINKS_MAX_URLS + 10))
        node = minidom.parseString(
            '<activity xmlns:android="http://schemas.android.com/apk/res/'
            'android"><intent-filter><category android:name="android.'
            f'intent.category.BROWSABLE"/>{hosts}</intent-filter>'
            '</activity>').documentElement
        with mock.patch.object(
                manifest_analysis, 'valid_host',
                return_value=False) as valid_host:
            browse_dic = get_browsable_activities(node, 'android')
            valid_host.assert_not_called()
            findings = assetlinks_check(
                'A', browse_dic['well_known'], new_assetlinks_budget())
        self.assertEqual(valid_host.call_count, ASSETLINKS_MAX_URLS)
        # Hosts that aren't publicly routable produce no finding.
        self.assertEqual(findings, [])

    def test_request_limited_to_remaining_budget(self):
        budget = new_assetlinks_budget()
        budget['deadline'] = time.monotonic() + 5
        with mock.patch.object(
                manifest_analysis, 'valid_host', return_value=True), \
                mock.patch.object(
                    manifest_analysis, 'safe_request',
                    side_effect=TimeoutError) as request:
            findings = assetlinks_check('A', well_knowns(1), budget)
        self.assertLessEqual(request.call_args.kwargs['max_total_time'], 5)
        self.assertIsNone(findings[0]['status_code'])


class FirebaseDbLimitTests(SimpleTestCase):

    def test_one_https_origin_per_host(self):
        urls = ['http://p.firebaseio.com/path', 'https://p.firebaseio.com',
                'https://P.firebaseio.com:443/other']
        with mock.patch.object(
                firebase, 'open_firebase',
                side_effect=lambda checksum, url: (url, False)) as opener:
            firebase.firebase_db_check('x', {'urls_list': urls})
        self.assertEqual(
            [call.args[1] for call in opener.call_args_list],
            ['https://p.firebaseio.com'])

    def test_hosts_deduplicated_and_capped(self):
        urls = [f'https://p{i}.firebaseio.com/path{j}'
                for i in range(firebase.MAX_FIREBASE_DB_HOSTS + 5)
                for j in range(3)]
        with mock.patch.object(
                firebase, 'open_firebase',
                side_effect=lambda checksum, url: (url, False)) as opener:
            firebase.firebase_db_check('x', {'urls_list': urls})
        hosts = {call.args[1].split('/')[2] for call in opener.call_args_list}
        self.assertEqual(opener.call_count, firebase.MAX_FIREBASE_DB_HOSTS)
        self.assertEqual(len(hosts), firebase.MAX_FIREBASE_DB_HOSTS)
