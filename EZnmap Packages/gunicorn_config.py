# gunicorn_config.py

import os

########################################################################
# Example: Set an environment variable so each Gunicorn worker sees the
# same "EZNMAP_SECRET_KEY". This prevents session issues where random
# keys might differ between workers.
########################################################################
EZNMAP_SECRET_KEY = os.getenv("EZNMAP_SECRET_KEY", "some-32-char-secret-here")

# Bind to an address and port
bind = "0.0.0.0:5000"

# Number of worker processes (adjust based on CPU cores or load)
workers = 4

# Timeout for workers (seconds)
timeout = 600

# Logging level
loglevel = "info"

########################################################################
# raw_env: a list of raw environment variables to pass to the workers.
# This ensures every worker sees the same "EZNMAP_SECRET_KEY".
########################################################################
raw_env = [
    f"EZNMAP_SECRET_KEY={EZNMAP_SECRET_KEY}",
]

