import os
import sys
import urllib.parse

# Ensure the project root directory is in sys.path so app, db, scorer modules are found
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app


class VercelMiddleware:
    """WSGI Middleware for Vercel Serverless Functions.

    Extracts the true requested path from the query parameter __route__
    (injected via vercel.json rewrite) or from Vercel edge proxy headers,
    and sets environ["PATH_INFO"] before Flask evaluates routes.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        target_path = None

        # 1. First priority: Check __route__ or path in the query string
        query_string = environ.get("QUERY_STRING", "")
        if "__route__" in query_string or "path=" in query_string:
            qs_dict = urllib.parse.parse_qs(query_string)
            if "__route__" in qs_dict and qs_dict["__route__"]:
                target_path = qs_dict["__route__"][0]
            elif "path" in qs_dict and qs_dict["path"]:
                target_path = qs_dict["path"][0]

            if target_path:
                clean_params = [
                    (k, v)
                    for k, vs in qs_dict.items()
                    if k not in ("__route__", "path")
                    for v in vs
                ]
                environ["QUERY_STRING"] = urllib.parse.urlencode(clean_params)

        # 2. Second priority: Check Vercel edge proxy headers
        if not target_path or target_path in ("/api/index", ""):
            for header_key in (
                "HTTP_X_MATCHED_PATH",
                "HTTP_X_FORWARDED_URI",
                "HTTP_X_ORIGINAL_URL",
            ):
                val = environ.get(header_key)
                if val and not val.startswith("/api/index"):
                    target_path = val.split("?")[0]
                    break

        # 3. Third priority: Check PATH_INFO suffix if it was /api/index/...
        if not target_path or target_path in ("/api/index", ""):
            current_path = environ.get("PATH_INFO", "")
            if current_path.startswith("/api/index"):
                rest = current_path[len("/api/index"):]
                target_path = rest if rest else "/"
            else:
                target_path = current_path or "/"

        # Ensure path starts with "/"
        if not target_path.startswith("/"):
            target_path = "/" + target_path

        # Clean trailing slashes except for root
        if len(target_path) > 1 and target_path.endswith("/"):
            target_path = target_path.rstrip("/")

        environ["PATH_INFO"] = target_path
        return self.wsgi_app(environ, start_response)


# Wrap Flask's WSGI application with Vercel path handling
app.wsgi_app = VercelMiddleware(app.wsgi_app)
