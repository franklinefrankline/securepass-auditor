import os
import sys

# Ensure the project root directory is in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app


class IndexMiddleware:
    """WSGI Middleware for handling all routes on Vercel."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        query = environ.get("QUERY_STRING", "")
        matched_path = (
            environ.get("HTTP_X_MATCHED_PATH")
            or environ.get("HTTP_X_FORWARDED_URI")
            or environ.get("HTTP_X_ORIGINAL_URL")
            or environ.get("REQUEST_URI")
            or ""
        )

        # Static files pass through directly
        if path.startswith("/static/"):
            return self.wsgi_app(environ, start_response)

        # Route matching based on query parameter or matched path
        if (
            "__route__=history" in query
            or "path=history" in query
            or "view=history" in query
            or "/history" in matched_path
            or path == "/history"
        ):
            environ["PATH_INFO"] = "/history"
        elif (
            "__route__=check" in query
            or "path=check" in query
            or "/check" in matched_path
            or path == "/check"
        ):
            environ["PATH_INFO"] = "/check"
        elif (
            "__route__=health" in query
            or "path=health" in query
            or "/health" in matched_path
            or path == "/health"
        ):
            environ["PATH_INFO"] = "/health"
        elif (
            "__route__=generate" in query
            or "path=generate" in query
            or "/generate" in matched_path
            or path == "/generate"
        ):
            environ["PATH_INFO"] = "/generate"
        elif path.startswith("/api/index"):
            rest = path[len("/api/index"):]
            if rest in ("/history", "/check", "/health", "/generate"):
                environ["PATH_INFO"] = rest
            else:
                environ["PATH_INFO"] = rest if rest else "/"

        return self.wsgi_app(environ, start_response)


# Main serverless handler for /
app.wsgi_app = IndexMiddleware(app.wsgi_app)
