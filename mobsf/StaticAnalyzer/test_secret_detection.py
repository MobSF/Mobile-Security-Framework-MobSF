"""Tests for known secret detection."""
from unittest import TestCase

from mobsf.StaticAnalyzer.views.common.secret_detection import (
    detect_known_secrets,
    get_secrets,
    sort_secrets,
)


class SecretDetectionTests(TestCase):
    """Test known and entropy-based secret detection."""

    def test_detects_high_confidence_prefixed_secrets(self):
        """Detect secret formats with strong provider prefixes."""
        values = {
            'GitHub token': f'ghp_{"A1" * 18}',
            'GitHub fine-grained token': f'github_pat_{"Ab_" * 20}',
            'GitLab personal access token': f'glpat-{"Ab-_" * 6}',
            'Slack token': f'xoxb-{"A1-" * 8}',
            'Slack webhook': (
                'https://hooks.slack.com/services/'
                f'T{"A1" * 4}/B{"C2" * 4}/{"Ab1" * 8}'),
            'Stripe live secret key': f'sk_live_{"A1" * 12}',
            'SendGrid API key': f'SG.{"Ab1_" * 5}.{"Cd2-" * 8}',
            'npm access token': f'npm_{"A1" * 18}',
            'Mapbox secret token': f'sk.{"Ab1_" * 8}.{"Cd2-" * 8}',
            'Anthropic API key': (
                f'sk-ant-api03-{"Ab_" * 31}AA'),
            'OpenAI API key': (
                f'sk-{"A1" * 10}T3BlbkFJ{"B2" * 10}'),
            'Hugging Face access token': f'hf_{"Ab" * 17}',
            'DigitalOcean token': f'dop_v1_{"a1" * 32}',
            'Doppler API token': f'dp.pt.{"A1" * 21}A',
            'Brevo API token': (
                f'xkeysib-{"a1" * 32}-{"A1" * 8}'),
            'Sentry user token': f'sntryu_{"a1" * 32}',
            'Shopify access token': f'shpat_{"a1" * 16}',
            'Square access token': f'sq0atp-{"A1_-" * 6}',
            'Private key': '-----BEGIN PRIVATE KEY-----',
        }

        secrets = detect_known_secrets(values.values())

        self.assertEqual(
            secrets,
            {f'{name}: {value}' for name, value in values.items()})

    def test_detects_and_labels_amazon_lwa_secrets(self):
        """Detect complete Amazon LWA credential values."""
        client_secret = f'amzn1.oa2-cs.v1.{"a1" * 32}'
        access_token = f'Atza|{"Ab1_" * 10}'
        refresh_token = f'Atzr|{"Cd2-" * 10}'

        secrets = detect_known_secrets(
            (client_secret, access_token, refresh_token))

        self.assertEqual(secrets, {
            f'Amazon LWA client secret: {client_secret}',
            f'Amazon LWA access token: {access_token}',
            f'Amazon LWA refresh token: {refresh_token}',
        })

    def test_does_not_classify_amazon_identifiers_as_secrets(self):
        """Ignore public Amazon application and account identifiers."""
        identifiers = (
            'amzn1.application-oa2-client.0123456789abcdef',
            'amzn1.application.0123456789abcdef',
            'amzn1.ask.skill.01234567-89ab-cdef-0123-456789abcdef',
            'amzn1.account.ABCDEFGHIJKL',
            f'pk.{"Ab1_" * 8}.{"Cd2-" * 8}',
            f'sk_test_{"A1" * 12}',
        )

        self.assertEqual(detect_known_secrets(identifiers), set())

    def test_rejects_bare_or_short_token_prefixes(self):
        """Ignore SDK markers and truncated tokens."""
        values = ('Atza|', 'Atzr|', 'Atza|short', 'Atzr|short')

        self.assertEqual(detect_known_secrets(values), set())

    def test_known_secret_is_not_duplicated_as_entropy(self):
        """Suppress anonymous entropy fragments from a typed secret."""
        client_secret = f'amzn1.oa2-cs.v1.{"a1" * 32}'

        self.assertEqual(
            get_secrets(client_secret),
            {f'Amazon LWA client secret: {client_secret}'})

    def test_retains_generic_entropy_detection(self):
        """Keep detecting unknown high-entropy strings."""
        unknown_secret = 'A1b2C3d4E5f6G7h8I9j0KLMNOPqrstUV'

        self.assertIn(unknown_secret, get_secrets((unknown_secret,)))

    def test_large_near_matches_complete_without_backtracking(self):
        """Reject large near matches without catastrophic backtracking."""
        long_value = 'A' * 250_000
        near_matches = (
            f'ghp_{long_value}',
            f'github_pat_{long_value}',
            f'glpat-{long_value}',
            f'xoxb-{long_value}',
            f'SG.{long_value}.{long_value}',
            f'sk.{long_value}.{long_value}',
            f'sk-ant-api03-{long_value}',
            f'sk-proj-{long_value}T3BlbkFJ{long_value}',
            f'hf_{long_value}',
            f'xkeysib-{long_value}-{long_value}',
            f'sq0atp-{long_value}',
            f'Atza|{long_value}',
        )

        self.assertEqual(detect_known_secrets(near_matches), set())

    def test_sorts_known_secrets_before_heuristic_findings(self):
        """Keep labeled known secrets at the top of reports."""
        secrets = (
            'z9Y8x7W6v5U4t3S2r1Q0',
            'Slack token: xoxb-example',
            '"api_key" : "possible-secret"',
            'GitHub token: ghp_example',
        )

        self.assertEqual(sort_secrets(secrets), [
            'GitHub token: ghp_example',
            'Slack token: xoxb-example',
            '"api_key" : "possible-secret"',
            'z9Y8x7W6v5U4t3S2r1Q0',
        ])
