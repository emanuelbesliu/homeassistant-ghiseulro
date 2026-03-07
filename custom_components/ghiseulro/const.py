"""Constants for the Ghiseul.ro integration.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License
"""

DOMAIN = "ghiseulro"

# API endpoints
BASE_URL = "https://www.ghiseul.ro/ghiseul/public"
LOGIN_URL = f"{BASE_URL}/login/process"
DEBITE_URL = f"{BASE_URL}/debite"
DEBITE_INSTITUTII_URL = f"{BASE_URL}/debite/institutii"
DEBITE_INSTITUTION_DETAILS_URL = f"{BASE_URL}/debite/get-institution-details/id_inst/{{id_inst}}"
DEBITE_ANAF_URL = f"{BASE_URL}/debite/anaf"
DEBITE_INCARCA_ANAF_URL = f"{BASE_URL}/debite/incarca-debite-anaf"
LOGOUT_URL = f"{BASE_URL}/login/logout"
IS_LOGGED_IN_URL = f"{BASE_URL}/index/este-logat"

# ANAF institution ID on ghiseul.ro
ANAF_INSTITUTION_ID = "3627"

# Update interval - 4 times per day (every 6 hours)
DEFAULT_SCAN_INTERVAL = 21600  # 6 hours in seconds
