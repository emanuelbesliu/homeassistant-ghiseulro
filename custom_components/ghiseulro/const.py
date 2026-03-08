"""Constants for the Ghiseul.ro integration.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License
"""

DOMAIN = "ghiseulro"

# Update interval - 4 times per day (every 6 hours)
DEFAULT_SCAN_INTERVAL = 21600  # 6 hours in seconds

# ghiseul-browser microservice configuration
CONF_BROWSER_SERVICE_URL = "browser_service_url"
DEFAULT_BROWSER_SERVICE_URL = "http://10.0.102.10:8192"

# ANAF institution ID on ghiseul.ro
ANAF_INSTITUTION_ID = "3627"
