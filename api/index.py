import os
import sys

# Ensure the project root directory is in sys.path so app, db, scorer modules are found
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app


class VercelMiddleware:
    """WSGI Middleware for Vercel Serverless Functions.

    Maps Vercel's rewritten paths (such as /api/index) back to the actual requested
    HTTP route using the HTTP_X_MATCHED_PATH header or by stripping the function prefix.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched = environ.get("HTTP_X_MATCHED_PATH")
        if matched and not matched.startswith("/api/index"):
            environ["PATH_INFO"] = matched
        elif environ.get("PATH_INFO", "").startswith("/api/index"):
            rest = environ["PATH_INFO"][len("/api/index"):]
            environ["PATH_INFO"] = rest if rest else "/"
        return self.wsgi_app(environ, start_response)


# Wrap Flask's WSGI application with Vercel path handling
app.wsgi_app = VercelMiddleware(app.wsgi_app)
