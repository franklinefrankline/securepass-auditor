import os
import sys

# Ensure the project root directory is in sys.path so app, db, scorer modules are found
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app

# Expose app for Vercel serverless WSGI runtime
app = app
