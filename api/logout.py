import os
import sys

# Ensure the project root directory is in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app


class LogoutMiddleware:
    """WSGI Middleware that routes directly to /logout in Flask."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        environ["PATH_INFO"] = "/logout"
        return self.wsgi_app(environ, start_response)


# Dedicated serverless handler for /logout
app.wsgi_app = LogoutMiddleware(app.wsgi_app)
