"""
Package: service
Package for the application models and service routes
This module creates and configures the Flask app and sets up the logging
and SQL database
"""
import sys
from flask import Flask
from service import config
from service.common import log_handlers
from flask_talisman import Talisman
from flask_cors import CORS

# Create Flask application
app = Flask(__name__)
app.config.from_object(config)

# Configure Talisman with security headers
talisman = Talisman(
    app,
    force_https=False,  # Set to True in production with HTTPS
    force_https_permanent=False,
    frame_options='DENY',  # X-Frame-Options: DENY
    frame_options_allow_from=None,
    content_security_policy={
        'default-src': "'self'",
        'object-src': "'none'",
    },
    content_security_policy_nonce_in=None,
    content_security_policy_report_only=False,
    referrer_policy='strict-origin-when-cross-origin',
    session_cookie_secure=False,  # Set to True in production
    session_cookie_http_only=True,
    session_cookie_samesite='Lax',
    strict_transport_security=True,
    strict_transport_security_preload=False,
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_include_subdomains=True,
    x_content_type_options=True,
    x_xss_protection=True,  # X-XSS-Protection: 1; mode=block
)

CORS(app)

# Import the routes After the Flask app is created
# pylint: disable=wrong-import-position, cyclic-import, wrong-import-order
from service import routes, models  # noqa: F401 E402

# pylint: disable=wrong-import-position
from service.common import error_handlers, cli_commands  # noqa: F401 E402

# Set up logging for production
log_handlers.init_logging(app, "gunicorn.error")

app.logger.info(70 * "*")
app.logger.info("  A C C O U N T   S E R V I C E   R U N N I N G  ".center(70, "*"))
app.logger.info(70 * "*")

try:
    models.init_db(app)  # make our database tables
except Exception as error:  # pylint: disable=broad-except
    app.logger.critical("%s: Cannot continue", error)
    # gunicorn requires exit code 4 to stop spawning workers when they die
    sys.exit(4)

app.logger.info("Service initialized!")

