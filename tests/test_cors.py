import importlib
import asyncio
import os
import unittest
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
import server

class CorsTests(unittest.TestCase):
    def test_pages_origin_preflight(self):
        with patch.dict(os.environ, {'ALLOWED_ORIGINS': 'https://umini1002.github.io'}):
            module = importlib.reload(server)
            async def check():
                async with AsyncClient(transport=ASGITransport(app=module.app), base_url='https://api.example.com') as client:
                    response = await client.options('/api/analyze', headers={
                        'Origin': 'https://umini1002.github.io',
                        'Access-Control-Request-Method': 'POST',
                        'Access-Control-Request-Headers': 'content-type',
                    })
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.headers['access-control-allow-origin'], 'https://umini1002.github.io')
                    denied = await client.options('/api/analyze', headers={'Origin': 'https://unrelated.example', 'Access-Control-Request-Method': 'POST'})
                    self.assertEqual(denied.status_code, 400)
            asyncio.run(check())
        importlib.reload(server)

if __name__ == '__main__':
    unittest.main()
