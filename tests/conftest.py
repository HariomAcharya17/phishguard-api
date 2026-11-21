import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "frontend", "api"))

# Tests never touch the network or the real database.
os.environ["PHISHGUARD_OFFLINE"] = "1"
for var in ("SUPABASE_URL", "SUPABASE_KEY", "VIRUSTOTAL_API_KEY", "WHOIS_API_KEY"):
    os.environ[var] = ""
