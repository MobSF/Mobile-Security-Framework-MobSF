"""Synthetic, offline regressions for scope, redaction, persistence and access."""
from datetime import timedelta
import json
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from mobsf.BugBounty.discovery import discover, endpoint_record
from mobsf.BugBounty.forms import ProgramForm
from mobsf.BugBounty.models import (
    Analysis, Endpoint, Evidence, Finding, FindingEvent, Program,
)
from mobsf.BugBounty.sanitization import REDACTED, redact_text, sanitize
from mobsf.BugBounty.scope import authorize_active, classify, validate_rules
from mobsf.BugBounty.services import (
    add_evidence, import_core, import_har, review_finding,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid, StaticAnalyzerIOS

TOKEN = 'ghp_' + 'A' * 36


class ScopeTests(SimpleTestCase):
    def setUp(self):
        self.program = SimpleNamespace(
            rules={'allowed_domains': ['example.test'],
                   'allowed_subdomains': ['example.test'],
                   'excluded_domains': ['blocked.example.test'],
                   'excluded_paths': ['/admin']},
            approved=True, authorization_source='Synthetic authorization',
            authorized_at=timezone.now())

    def test_exact_and_subdomain_matching(self):
        for url in ('https://example.test/', 'https://api.example.test/'):
            self.assertEqual(classify(url, self.program), 'IN_SCOPE')
        for host in ('evilexample.test', 'example.test.evil.test'):
            self.assertEqual(classify('https://' + host, self.program), 'UNKNOWN')

    def test_exclusion_precedence_and_path_boundaries(self):
        for url in ('https://blocked.example.test/',
                    'https://example.test/admin',
                    'https://example.test/%61dmin/settings'):
            self.assertEqual(classify(url, self.program), 'OUT_OF_SCOPE')
        self.assertEqual(classify(
            'https://example.test/administrator', self.program), 'IN_SCOPE')

    def test_authorization_metadata_required(self):
        self.program.approved = False
        self.assertEqual(classify('https://example.test', self.program), 'UNKNOWN')
        self.program.approved = True
        self.program.authorization_source = ''
        self.assertEqual(classify('https://example.test', self.program), 'UNKNOWN')

    def test_wildcard_does_not_authorize_apex(self):
        self.program.rules = {'allowed_domains': ['*.example.test']}
        self.assertEqual(classify('https://example.test', self.program), 'UNKNOWN')
        self.assertEqual(classify('https://api.example.test', self.program),
                         'IN_SCOPE')

    def test_ambiguous_and_credential_urls_unknown(self):
        for url in ('https://example.test/%252e%252e/admin',
                    'https://example.test/a/../admin',
                    'https://example.test/a\\admin',
                    'https://example.test//admin',
                    'https://example.test/admin;session=value',
                    'https://user:pass@example.test/',
                    'https://example.test:bad/', 'file:///etc/passwd',
                    'https://example.test/[REDACTED]'):
            self.assertEqual(classify(url, self.program), 'UNKNOWN')

    def test_invalid_scope_rules_rejected(self):
        for rules in ({'allow_all': True}, {'allowed_domains': '*'},
                      {'allowed_domains': ['example.test/evil']},
                      {'allowed_domains': ['a..test']},
                      {'excluded_paths': ['admin']}):
            with self.assertRaises(ValueError):
                validate_rules(rules)

    def test_idna_and_trailing_dot(self):
        self.program.rules = {'allowed_domains': ['xn--bcher-kva.test']}
        self.assertEqual(classify('https://BÜCHER.test./', self.program),
                         'IN_SCOPE')

    def test_active_testing_always_blocked(self):
        with self.assertRaises(PermissionError):
            authorize_active('https://example.test', self.program)

    def test_yaml_aliases_and_unsupported_keys_rejected(self):
        for text in ('allowed_domains: &a [example.test]\nexcluded_domains: *a',
                     'allow_all: true'):
            form = ProgramForm({'name': 'Synthetic', 'rules': text})
            self.assertFalse(form.is_valid())

    def test_safe_yaml_configuration(self):
        form = ProgramForm({'name': 'Synthetic',
                            'rules': 'allowed_domains:\n  - example.test'})
        self.assertTrue(form.is_valid(), form.errors)


class DiscoveryTests(SimpleTestCase):
    def test_normalization_dedup_and_values_omitted(self):
        first = endpoint_record(
            'https://API.example.test:443/v1?token=secret&id=123#x', 'a.java')
        second = endpoint_record(
            'https://api.example.test/v1?id=456&token=another', 'b.kt')
        self.assertEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(first['parameters'], ['id', 'token'])
        self.assertNotIn('secret', first['url'])
        self.assertEqual(first['method'], '')

    def test_path_differences_preserved(self):
        paths = ('/users', '/Users', '/users/', '//users', '/%75sers')
        identities = {endpoint_record('https://example.test' + p, 'test')[
            'fingerprint'] for p in paths}
        self.assertEqual(len(identities), len(paths))

    def test_credentials_and_invalid_ports_rejected(self):
        for url in ('https://user:pass@example.test/',
                    'https://example.test:65536/', 'https://example.test/\n'):
            with self.assertRaises(ValueError):
                endpoint_record(url, 'test')

    def test_observed_method_requires_evidence(self):
        self.assertEqual(endpoint_record(
            'https://example.test', 'code', 'POST')['method'], '')
        self.assertEqual(endpoint_record(
            'https://example.test', 'HAR', 'POST', True)['method'], 'POST')

    def test_protocol_and_source_extraction(self):
        records = list(discover(
            'url="wss://example.test/socket"; https://example.test/graphql',
            'Main.smali'))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]['protocol'], 'WebSocket')
        self.assertEqual(records[1]['protocol'], 'GraphQL')
        self.assertEqual(records[0]['sources'], ['Main.smali'])

    def test_secret_path_is_redacted(self):
        record = endpoint_record('https://example.test/' + TOKEN, 'test')
        self.assertNotIn(TOKEN, record['url'])

    def test_invalid_method_and_secret_hostname(self):
        with self.assertRaises(ValueError):
            endpoint_record('https://example.test', 'HAR', ['GET'], True)
        with self.assertRaises(ValueError):
            endpoint_record('https://' + TOKEN + '.example.test/', 'test')
        token_label = 'a' * 40
        record = endpoint_record('https://' + token_label + '.example.test/', 'test')
        self.assertNotIn(token_label, record['host'])


class SanitizationTests(SimpleTestCase):
    def test_nested_credentials_and_personal_data(self):
        data = sanitize({'Authorization': 'Bearer abcd',
                         'nested': [{'cookie': 'private',
                                     'description': TOKEN + ' a@example.test'}]})
        self.assertEqual(data['Authorization'], REDACTED)
        self.assertNotIn(TOKEN, json.dumps(data))
        self.assertNotIn('a@example.test', json.dumps(data))

    def test_private_keys_and_logs(self):
        text = ('-----BEGIN PRIVATE KEY-----\nprivate bytes\n'
                '-----END PRIVATE KEY-----\nAuthorization: Basic secret\n'
                'password=hunter2 token=synthetic')
        safe = redact_text(text)
        for value in ('private bytes', 'hunter2', 'synthetic', 'Basic secret'):
            self.assertNotIn(value, safe)

    def test_evidence_depth_is_bounded(self):
        value = 'leaf'
        for _i in range(20):
            value = [value]
        with self.assertRaises(ValueError):
            sanitize(value)


class WorkspaceTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_superuser(
            'bb-owner', 'owner@example.test', 'test-only-password')
        self.other = user_model.objects.create_user('bb-other', password='test-only')
        self.program = Program.objects.create(
            owner=self.owner, name='Synthetic program', approved=True,
            authorized_at=timezone.now(), authorization_source='Local fixtures',
            rules={'allowed_domains': ['api.example.test'],
                   'excluded_paths': ['/admin']})
        self.core = StaticAnalyzerAndroid.objects.create(
            MD5='a' * 32, PACKAGE_NAME='test.synthetic.app', VERSION_NAME='1',
            URLS=str([{'urls': [
                'https://api.example.test/v1/users?token=private',
                'https://api.example.test/admin',
                'https://unknown.example.test/api'], 'path': 'Main.java'}]),
            STRINGS=str(['https://api.example.test/v1/users?token=another']),
            SECRETS=str(['GitHub token: ' + TOKEN]),
            CODE_ANALYSIS=str({'rule_tls': {
                'metadata': {'severity': 'high', 'description': 'TLS rule'},
                'files': {'Main.java': '42'}}}))
        self.client.force_login(self.owner)

    def import_analysis(self):
        with patch('requests.sessions.Session.request',
                   side_effect=AssertionError('Passive import used network')):
            return import_core(self.program, self.core.MD5)

    def test_core_import_is_passive_idempotent_and_persistent(self):
        analysis = self.import_analysis()
        self.import_analysis()
        self.assertEqual(Analysis.objects.count(), 1)
        self.assertEqual(analysis.endpoints.count(), 3)
        self.assertEqual(analysis.findings.count(), 5)
        self.assertFalse(analysis.findings.exclude(status='NEW').exists())
        self.assertFalse(analysis.endpoints.exclude(method='').exists())
        self.assertNotIn(TOKEN, json.dumps(list(
            Evidence.objects.values()), default=str))
        reopened = Client()
        reopened.force_login(self.owner)
        response = reopened.get(f'/bounty/api/analyses/{analysis.pk}/')
        self.assertEqual(response.status_code, 200)
        scopes = {e['scope_status'] for e in response.json()['endpoints']}
        self.assertEqual(scopes, {'IN_SCOPE', 'OUT_OF_SCOPE', 'UNKNOWN'})

    def test_cross_project_access_is_denied(self):
        analysis = self.import_analysis()
        finding = analysis.findings.first()
        self.client.force_login(self.other)
        for url in (f'/bounty/programs/{self.program.pk}/',
                    f'/bounty/analyses/{analysis.pk}/',
                    f'/bounty/findings/{finding.pk}/',
                    f'/bounty/analyses/{analysis.pk}/export/json/'):
            self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.post(
            f'/bounty/api/findings/{finding.pk}/evidence/',
            {'kind': 'manual', 'source': 'review', 'content': 'text'}).status_code,
            404)

    @override_settings(DISABLE_AUTHENTICATION='1')
    def test_global_api_key_cannot_bypass_workspace_auth(self):
        anonymous = Client()
        self.assertEqual(anonymous.get('/bounty/api/programs/').status_code, 302)

    def test_api_csrf_required(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.owner)
        response = client.post('/bounty/api/programs/',
                               {'name': 'Bad', 'rules': '{}'})
        self.assertEqual(response.status_code, 403)

    def test_api_program_creation_and_validation(self):
        response = self.client.post('/bounty/api/programs/', {
            'name': 'Second program', 'rules': {'allowed_domains': ['test.test']},
        }, content_type='application/json')
        self.assertEqual(response.status_code, 201)
        response = self.client.post('/bounty/api/programs/', {
            'name': 'Invalid', 'rules': {}, 'approved': True,
        }, content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_api_core_import_and_missing_report(self):
        url = f'/bounty/api/programs/{self.program.pk}/import/'
        self.assertEqual(self.client.post(url, {'checksum': 'z' * 32}).status_code,
                         400)
        self.assertEqual(self.client.post(url, {'checksum': 'b' * 32}).status_code,
                         400)
        self.assertEqual(self.client.post(url, {'checksum': 'a' * 32}).status_code,
                         200)
        self.assertEqual(self.client.get(url).status_code, 405)

    def test_import_requires_scan_permission(self):
        program = Program.objects.create(owner=self.other, name='Other')
        self.client.force_login(self.other)
        self.assertEqual(self.client.post(
            f'/bounty/api/programs/{program.pk}/import/',
            {'checksum': 'a' * 32}).status_code, 403)

    def test_manual_review_records_history_and_retains_state_on_import(self):
        analysis = self.import_analysis()
        finding = analysis.findings.first()
        review_finding(finding, self.owner, 'CONFIRMED', 'low',
                       'Manually verified on an authorized local fixture')
        self.import_analysis()
        finding.refresh_from_db()
        self.assertEqual(finding.status, 'CONFIRMED')
        self.assertEqual(FindingEvent.objects.count(), 1)

    def test_confirmation_requires_evidence_and_justification(self):
        analysis = self.import_analysis()
        finding = Finding.objects.create(
            analysis=analysis, fingerprint='c' * 64, title='Manual',
            kind='manual', rationale='Review required')
        for note in ('', 'No evidence'):
            with self.assertRaises(ValueError):
                review_finding(finding, self.owner, 'CONFIRMED', 'high', note)
        self.assertEqual(FindingEvent.objects.count(), 0)

    def test_sanitized_har_merges_static_dynamic_evidence(self):
        analysis = self.import_analysis()
        har = {'log': {'entries': [{'request': {
            'url': 'https://api.example.test/v1/users?token=' + TOKEN,
            'method': 'GET', 'headers': [
                {'name': 'Authorization', 'value': 'Bearer secret'}]},
            'response': {'status': 200, 'content': {'text': TOKEN}}}]}}
        self.assertEqual(import_har(analysis, har), 1)
        endpoint = analysis.endpoints.get(path='/v1/users')
        self.assertTrue(endpoint.observed)
        self.assertEqual(endpoint.method, 'GET')
        self.assertEqual(endpoint.sources, ['HAR', 'Main.java', 'STRINGS'])
        self.assertNotIn(TOKEN, json.dumps(list(
            Evidence.objects.values('content'))))
        self.assertEqual(analysis.endpoints.count(), 3)

    def test_multiple_observed_methods_not_invented(self):
        analysis = self.import_analysis()
        for method in ('GET', 'POST', 'PATCH'):
            import_har(analysis, {'log': {'entries': [{'request': {
                'url': 'https://api.example.test/v1/users?token=any',
                'method': method}}]}})
        endpoint = analysis.endpoints.get(path='/v1/users')
        self.assertEqual(endpoint.method, '')
        self.assertEqual(endpoint.methods, ['GET', 'PATCH', 'POST'])

    def test_har_invalid_input_rolls_back(self):
        analysis = self.import_analysis()
        count = Endpoint.objects.count()
        with self.assertRaises(ValueError):
            import_har(analysis, {'log': {'entries': [
                {'request': {'url': 'https://new.example.test', 'method': 'GET'}},
                {'request': {'url': 'file:///etc/passwd'}}]}})
        self.assertEqual(Endpoint.objects.count(), count)

    @override_settings(BOUNTY_MAX_IMPORT_BYTES=100)
    def test_request_limits(self):
        response = self.client.post('/bounty/api/programs/',
                                    {'name': 'A' * 200},
                                    content_type='application/json')
        self.assertEqual(response.status_code, 413)

    def test_manual_evidence_and_retention(self):
        finding = self.import_analysis().findings.first()
        ev = add_evidence(finding, 'frida', 'local/fixture.js',
                          {'password': 'private', 'message': TOKEN})
        self.assertEqual(len(ev.sha256), 64)
        self.assertNotIn(TOKEN, json.dumps(ev.content))
        ev.expires_at = timezone.now() - timedelta(seconds=1)
        ev.save()
        call_command('purge_bounty_evidence', verbosity=0)
        self.assertFalse(Evidence.objects.filter(pk=ev.pk).exists())
        self.assertTrue(Finding.objects.filter(pk=finding.pk).exists())

    def test_evidence_paths_and_findings_choices(self):
        finding = self.import_analysis().findings.first()
        self.assertEqual(self.client.post(
            f'/bounty/api/findings/{finding.pk}/evidence/',
            {'kind': 'manual', 'source': '../../escape',
             'content': 'text'}).status_code, 400)
        self.assertEqual(self.client.post(f'/bounty/api/findings/{finding.pk}/',
                                          {'status': 'INVALID', 'severity': 'high',
                                          'note': 'Test'}).status_code, 400)

    def test_inventory_exports_and_html_escaping(self):
        analysis = self.import_analysis()
        for fmt in ('json', 'csv'):
            response = self.client.get(
                f'/bounty/analyses/{analysis.pk}/export/{fmt}/')
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, TOKEN)
            self.assertNotContains(response, 'token=private')
        finding = analysis.findings.first()
        finding.title = '<script>alert(1)</script>'
        finding.save()
        response = self.client.get(f'/bounty/findings/{finding.pk}/')
        self.assertContains(response, '&lt;script&gt;')
        self.assertNotContains(response, '<script>alert(1)</script>')
        for url in ('/bounty/', f'/bounty/programs/{self.program.pk}/',
                    f'/bounty/analyses/{analysis.pk}/'):
            self.assertEqual(self.client.get(url).status_code, 200)

    def test_version_comparison_and_ios_import(self):
        first = self.import_analysis()
        ios = StaticAnalyzerIOS.objects.create(
            MD5='b' * 32, BUNDLE_ID='test.synthetic.app', APP_VERSION='2',
            URLS=str([{'urls': ['https://api.example.test/new'],
                       'path': 'Controller.swift'}]))
        second = import_core(self.program, ios.MD5)
        response = self.client.get(
            f'/bounty/analyses/{first.pk}/compare/{second.pk}/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['added'])
        self.assertTrue(response.json()['removed'])
        self.assertEqual(second.platform, 'ios')

    def test_finding_create_review_evidence_and_report_api(self):
        analysis = self.import_analysis()
        response = self.client.post(
            f'/bounty/api/analyses/{analysis.pk}/findings/',
            {'title': 'Synthetic issue', 'rationale': 'Local reproduction',
             'severity': 'low'})
        self.assertEqual(response.status_code, 201)
        pk = response.json()['finding_id']
        self.assertEqual(self.client.post(
            f'/bounty/api/findings/{pk}/evidence/',
            {'kind': 'manual', 'source': 'local/fixture',
             'content': 'password=private'}).status_code, 201)
        self.assertEqual(self.client.post(f'/bounty/api/findings/{pk}/', {
            'status': 'IN_REVIEW', 'severity': 'low',
            'note': 'Needs manual validation'}).status_code, 200)
        self.assertEqual(self.client.get(
            f'/bounty/api/findings/{pk}/').status_code, 200)
        for fmt in ('md', 'json'):
            response = self.client.get(f'/bounty/findings/{pk}/report/{fmt}/')
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, 'password=private')
