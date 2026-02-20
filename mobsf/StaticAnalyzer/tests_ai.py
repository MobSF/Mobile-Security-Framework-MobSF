from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch
import json


class MobSFAITests(TestCase):

    @patch("mobsf.StaticAnalyzer.ai.service.call_openai")
    def test_api_chat_success(self, mock_ai):
        """Test successful chat interaction via AI endpoint."""
        # Mock the AI service to return a structured response
        mock_ai.return_value = {"response": "This is a mocked bot response."}

        payload = {
            "hash": "test_hash_abc",
            "message": "What vulnerabilities do you see?",
            "history": []
        }

        # NOTE: Ensure 'api_chat' is the correct URL name in your urls.py
        # e.g., re_path(r'^api/v1/chat$', views.api_chat, name='api_chat')
        try:
            url = reverse('ai_endpoint_name')
        except Exception:
            # Fallback direct path if reverse fails (e.g. url pattern not yet named)
            url = "/api/v1/chat"

        response = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())
        self.assertEqual(response.json()["response"], "This is a mocked bot response.")

    def test_api_chat_missing_params(self):
        """Test AI endpoint with missing message parameter."""
        payload = {
            "scan_id": "123",
            # Missing 'message'
        }

        try:
            url = reverse('ai_endpoint_name')
        except Exception:
            url = "/api/v1/chat"

        response = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())
