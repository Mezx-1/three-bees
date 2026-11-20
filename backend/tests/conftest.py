"""Shared test environment: one temp DB/upload dir, offline (no AI, no external lookups)."""
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["THREEB_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db".replace("\\", "/")
os.environ["THREEB_UPLOAD_DIR"] = _tmp
os.environ["THREEB_EXTERNAL_LOOKUPS"] = "false"
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["THREEB_RATE_LIMIT_PER_MINUTE"] = "1000"
os.environ["THREEB_DEV_HEADER_AUTH"] = "true"  # tests use the X-3B-User shortcut; test_auth.py checks real sign-in
os.environ["THREEB_CREDENTIALS_FILE"] = f"{_tmp}/credentials.txt"
