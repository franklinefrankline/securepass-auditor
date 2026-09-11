import os
import sys

# Ensure the project root directory is in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app


class RegisterMiddleware:
    """WSGI Middleware that routes directly to /register in Flask."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        environ["PATH_INFO"] = "/register"
        return self.wsgi_app(environ, start_response)


# Dedicated serverless handler for /register
app.wsgi_app = RegisterMiddleware(app.wsgi_app)
