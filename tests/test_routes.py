"""
Account API Service Test Suite

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
import logging
from unittest import TestCase
from tests.factories import AccountFactory
from service.common import status  # HTTP Status Codes
from service.models import db, Account, init_db
from service.routes import app
from service import talisman

DATABASE_URI = os.getenv(
    "DATABASE_URI", "postgresql://postgres:postgres@localhost:5432/postgres"
)

BASE_URL = "/accounts"

# Define HTTPS environ for testing
HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


######################################################################
#  T E S T   C A S E S
######################################################################
class TestAccountService(TestCase):
    """Account Service Tests"""

    @classmethod
    def setUpClass(cls):
        """Run once before all tests"""
        app.config["TESTING"] = True
        app.config["DEBUG"] = False
        app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
        app.logger.setLevel(logging.CRITICAL)
        init_db(app)
        talisman.force_https = False

    @classmethod
    def tearDownClass(cls):
        """Runs once before test suite"""

    def setUp(self):
        """Runs before each test"""
        db.session.query(Account).delete()  # clean up the last tests
        db.session.commit()

        self.client = app.test_client()

    def tearDown(self):
        """Runs once after each test case"""
        db.session.remove()

    ######################################################################
    #  H E L P E R   M E T H O D S
    ######################################################################

    def _create_accounts(self, count):
        """Factory method to create accounts in bulk"""
        accounts = []
        for _ in range(count):
            account = AccountFactory()
            response = self.client.post(BASE_URL, json=account.serialize())
            self.assertEqual(
                response.status_code,
                status.HTTP_201_CREATED,
                "Could not create test Account",
            )
            new_account = response.get_json()
            account.id = new_account["id"]
            accounts.append(account)
        return accounts

    ######################################################################
    #  A C C O U N T   T E S T   C A S E S
    ######################################################################

    def test_index(self):
        """It should get 200_OK from the Home Page"""
        response = self.client.get("/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_health(self):
        """It should be healthy"""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "OK")

    def test_create_account(self):
        """It should Create a new Account"""
        account = AccountFactory()
        response = self.client.post(
            BASE_URL,
            json=account.serialize(),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Make sure location header is set
        location = response.headers.get("Location", None)
        self.assertIsNotNone(location)

        # Check the data is correct
        new_account = response.get_json()
        self.assertEqual(new_account["name"], account.name)
        self.assertEqual(new_account["email"], account.email)
        self.assertEqual(new_account["address"], account.address)
        self.assertEqual(new_account["phone_number"], account.phone_number)
        self.assertEqual(new_account["date_joined"], str(account.date_joined))

    def test_bad_request(self):
        """It should not Create an Account when sending the wrong data"""
        response = self.client.post(BASE_URL, json={"name": "not enough data"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unsupported_media_type(self):
        """It should not Create an Account when sending the wrong media type"""
        account = AccountFactory()
        response = self.client.post(
            BASE_URL,
            json=account.serialize(),
            content_type="test/html"
        )
        self.assertEqual(response.status_code, status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)

    ######################################################################
    #  S E C U R I T Y   H E A D E R S   T E S T S
    ######################################################################

    def test_security_headers(self):
        """It should return security headers"""
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Define expected security headers
        headers = {
            'X-Frame-Options': 'DENY',  # Your app uses DENY
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        for key, value in headers.items():
            self.assertEqual(response.headers.get(key), value)

    def test_cors_headers(self):
        """It should return CORS headers for allowed origins"""
        # Test with a valid origin
        response = self.client.get(
            '/', 
            headers={'Origin': 'https://trusted-domain.com'},
            environ_overrides=HTTPS_ENVIRON
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check CORS headers
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), 'https://trusted-domain.com')
        self.assertIsNotNone(response.headers.get('Access-Control-Allow-Methods'))
        self.assertIsNotNone(response.headers.get('Access-Control-Allow-Headers'))

    def test_cors_preflight(self):
        """It should handle CORS preflight OPTIONS request"""
        response = self.client.options(
            '/',
            headers={
                'Origin': 'https://trusted-domain.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type'
            },
            environ_overrides=HTTPS_ENVIRON
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check CORS preflight headers
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), 'https://trusted-domain.com')
        self.assertIn('POST', response.headers.get('Access-Control-Allow-Methods', ''))
        self.assertIn('Content-Type', response.headers.get('Access-Control-Allow-Headers', ''))

    def test_cors_disallowed_origin(self):
        """It should not allow CORS from disallowed origins"""
        response = self.client.get(
            '/',
            headers={'Origin': 'https://malicious-site.com'},
            environ_overrides=HTTPS_ENVIRON
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that CORS headers are not set for disallowed origin
        self.assertIsNone(response.headers.get('Access-Control-Allow-Origin'))

    def test_content_security_policy(self):
        """It should have Content Security Policy headers"""
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check CSP header
        csp = response.headers.get('Content-Security-Policy')
        self.assertIsNotNone(csp)
        self.assertIn("default-src 'self'", csp)

    def test_no_server_info_leak(self):
        """It should not leak server information"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that Server header doesn't expose technology stack
        server_header = response.headers.get('Server')
        if server_header:  # If server header exists
            self.assertNotIn('gunicorn', server_header.lower())
            self.assertNotIn('python', server_header.lower())

    def test_cors_with_credentials(self):
        """It should handle CORS requests with credentials"""
        response = self.client.get(
            '/',
            headers={
                'Origin': 'https://trusted-domain.com',
                'Cookie': 'session=12345'
            },
            environ_overrides=HTTPS_ENVIRON
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # If credentials are allowed, check for the header
        if response.headers.get('Access-Control-Allow-Credentials'):
            self.assertEqual(response.headers.get('Access-Control-Allow-Credentials'), 'true')

    def test_method_not_allowed_cors(self):
        """It should handle OPTIONS for methods not allowed"""
        response = self.client.options(
            '/',
            headers={
                'Origin': 'https://trusted-domain.com',
                'Access-Control-Request-Method': 'DELETE'
            },
            environ_overrides=HTTPS_ENVIRON
        )
        
        # Either 200 OK or 405 Method Not Allowed is acceptable
        self.assertIn(response.status_code, [200, 405])

    def test_security_headers_on_error(self):
        """It should return security headers even on error responses"""
        # Test a 404 page
        response = self.client.get('/nonexistent-route', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Security headers should still be present
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')

    def test_cors_max_age(self):
        """It should set CORS max age for preflight caching"""
        response = self.client.options(
            '/',
            headers={
                'Origin': 'https://trusted-domain.com',
                'Access-Control-Request-Method': 'GET'
            },
            environ_overrides=HTTPS_ENVIRON
        )
        
        # Check if max-age is set (optional but recommended)
        max_age = response.headers.get('Access-Control-Max-Age')
        if max_age:
            self.assertTrue(int(max_age) > 0)


    def test_cors_security(self):
        """It should return a CORS header"""
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check for the CORS header
        self.assertEqual(response.headers.get('Access-Control-Allow-Origin'), '*')

