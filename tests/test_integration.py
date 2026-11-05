import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient
from server import app
from analysis_pipeline import analyze_url, RULE_MAX_SCORE


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_real_pipeline_reports(self):
        self.assertEqual(RULE_MAX_SCORE, 20)
        for url in ['https://www.google.com', 'http://example-login.xyz', 'https://example.com/account']:
            response = self.client.post('/api/analyze', json={'url': url})
            self.assertEqual(response.status_code, 200, response.text)
            report = response.json()
            self.assertIn(report['risk_level'], ['LOW', 'MEDIUM', 'HIGH'])
            self.assertTrue(0 <= report['risk_score'] <= 100)
            self.assertIsInstance(report['reason'], list)
            self.assertEqual(report['rule_score'], report['features']['risk_score'])
            self.assertNotIn('계정 정보 탈취형', report['attack_type'])
            self.assertEqual(len([key for key in report['features'] if key in __import__('feature_extractor').FEATURE_COLUMNS]), 23)

    def test_http_and_keyword_reasons(self):
        report = analyze_url('http://example-login.xyz')
        self.assertIn('HTTPS 대신 HTTP를 사용합니다.', report['reason'])
        self.assertTrue(any('login' in reason for reason in report['reason']))
        self.assertIn('has_caution_tld', report['matched_rules'])

    def test_invalid(self):
        for url in ['javascript://example.com', 'https://', 'not a url', 'https://example.com:bad']:
            with self.subTest(url=url):
                self.assertEqual(self.client.post('/api/analyze', json={'url': url}).status_code, 422)

    def test_model_missing(self):
        with patch('server.analyze_url', side_effect=FileNotFoundError):
            self.assertEqual(self.client.post('/api/analyze', json={'url': 'https://example.com'}).status_code, 503)

    def test_same_web_and_api(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        page = self.client.get('/').text
        self.assertIn('id="reasons"', page)
        self.assertNotIn('id="api"', page)
        self.assertTrue(self.client.get('/api/health').json()['model_ready'])
        self.assertEqual(self.client.get('/samples.json').status_code, 200)


if __name__ == '__main__':
    unittest.main()
