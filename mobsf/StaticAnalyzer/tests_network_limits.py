"""Limits on outbound requests driven by scanned app content."""
import threading
import time
from unittest import mock

from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.android import manifest_analysis
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    ASSETLINKS_MAX_URLS,
    assetlinks_check,
    new_assetlinks_budget,
)
from mobsf.StaticAnalyzer.views.common import firebase


def well_knowns(count, prefix='h'):
    return {
        f'https://{prefix}{i}.example.com/.well-known/assetlinks.json':
            f'https://{prefix}{i}.example.com'
        for i in range(count)}


def ok_result(host, w_url):
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

        def stalled(host, w_url):
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


class FirebaseDbLimitTests(SimpleTestCase):

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
