"""Passive Burp XML/Caido HAR regression tests, including ownership and redaction."""

import base64
import json

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from mobsf.BugBounty.models import Analysis, Evidence, Program
from mobsf.BugBounty.proxy_import import burp_items
from mobsf.BugBounty.services import import_har


class ProxyImportTests(TestCase):

    def setUp(self):
        self.user = get_user_model().objects.create_user('proxy-user')
        self.program = Program.objects.create(owner=self.user, name='Local fixture')
        self.analysis = Analysis.objects.create(
            program=self.program,
            checksum='a' * 32,
            platform='android',
            package='test.mobsf.proxy',
        )

    def burp_fixture(self):
        request = (
            b'GET /users?token=private-value HTTP/1.1\r\n'
            b'Host: api.example.test\r\nAuthorization: Bearer secret\r\n'
            b'Cookie: private-cookie\r\n\r\nprivate-request-body'
        )
        encoded = base64.b64encode(request).decode()
        return (
            f'<items><item><url>https://api.example.test/users?token=private-value'
            f'</url><method>GET</method><status>200</status>'
            f'<request base64="true">{encoded}</request>'
            f'<response>private-response-body</response></item></items>'
        ).encode()

    def test_burp_base64_import_preserves_provenance_and_redacts_secrets(self):
        data = burp_items(self.burp_fixture())
        self.assertEqual(
            import_har(self.analysis, data, 'Burp Suite Professional XML'), 1,
        )
        endpoint = self.analysis.endpoints.get()
        self.assertTrue(endpoint.observed)
        self.assertIn('Burp Suite Professional XML', endpoint.sources)
        self.assertEqual(endpoint.url, 'https://api.example.test/users?token=')
        evidence = json.dumps(list(Evidence.objects.values()), default=str)
        for secret in (
            'Bearer secret',
            'private-cookie',
            'private-value',
            'private-request-body',
            'private-response-body',
        ):
            self.assertNotIn(secret, evidence)

    def test_xml_entities_dtds_and_bad_base64_are_rejected(self):
        documents = (
            b'<!DOCTYPE items [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            b'<items><item><url>&x;</url></item></items>',
            b'<items><item><request base64="true">bad~base64</request>'
            b'</item></items>',
            b'<unexpected/>',
        )
        for data in documents:
            with self.subTest(data=data), self.assertRaises(ValueError):
                burp_items(data)
        self.assertFalse(self.analysis.endpoints.exists())

    def test_authenticated_burp_upload_and_unknown_format_rejection(self):
        self.client.force_login(self.user)
        url = f'/bounty/api/analyses/{self.analysis.pk}/har/'
        response = self.client.post(
            url,
            {
                'format': 'burp',
                'har': SimpleUploadedFile(
                    'items.xml', self.burp_fixture(), content_type='application/xml',
                ),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['imported'], 1)
        response = self.client.post(
            url,
            {
                'format': 'invalid',
                'har': SimpleUploadedFile('items.xml', self.burp_fixture()),
            },
        )
        self.assertEqual(response.status_code, 400)
        self.client.force_login(
            get_user_model().objects.create_user('other-proxy-user'),
        )
        self.assertEqual(self.client.post(url).status_code, 404)

    def test_caido_har_is_imported_without_network_or_body_storage(self):
        self.client.force_login(self.user)
        har = {
            'log': {
                'entries': [
                    {
                        'request': {
                            'url': 'https://api.example.test/graphql?key=private',
                            'method': 'POST',
                            'postData': {'text': 'private-body'},
                        },
                        'response': {'status': 200},
                    },
                ],
            },
        }
        response = self.client.post(
            f'/bounty/api/analyses/{self.analysis.pk}/har/',
            {
                'format': 'caido',
                'har': SimpleUploadedFile('caido.har', json.dumps(har).encode()),
            },
        )
        self.assertEqual(response.status_code, 200)
        endpoint = self.analysis.endpoints.get()
        self.assertIn('Caido HAR', endpoint.sources)
        self.assertEqual(endpoint.method, 'POST')
        self.assertNotIn(
            'private-body', json.dumps(list(Evidence.objects.values()), default=str),
        )
