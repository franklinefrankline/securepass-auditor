import os
import sys

# Ensure the project root directory is in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app


class IndexMiddleware:
    """WSGI Middleware for the main auditor interface on Vercel."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path.startswith("/static/"):
            return self.wsgi_app(environ, start_response)
        if path.startswith("/api/index"):
            rest = path[len("/api/index"):]
            environ["PATH_INFO"] = rest if rest else "/"
        return self.wsgi_app(environ, start_response)


# Main serverless handler for /
app.wsgi_app = IndexMiddleware(app.wsgi_app)
