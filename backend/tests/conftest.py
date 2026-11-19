"""Shared test environment: one temp DB/upload dir, offline (no AI, no external lookups)."""
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["WOLVE_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db".replace("\\", "/")
os.environ["WOLVE_UPLOAD_DIR"] = _tmp
os.environ["WOLVE_EXTERNAL_LOOKUPS"] = "false"
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["WOLVE_RATE_LIMIT_PER_MINUTE"] = "1000"
os.environ["WOLVE_DEV_HEADER_AUTH"] = "true"  # tests use the X-WOLVE-User shortcut; test_auth.py checks real sign-in
os.environ["WOLVE_CREDENTIALS_FILE"] = f"{_tmp}/credentials.txt"
