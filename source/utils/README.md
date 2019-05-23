# BroAPT Utility Scripts

## Generation Utility

`fix-missing.py` is to read `${LOGS_PATH}/processed_mime.log`, which lists unexpected MIMEs missing
in Bro script `file-extensions.bro`, and try to fix and update the missing mappings.

`mime2ext.py` is to generate and update the mappings listed in Bro script `file-extensions.bro`.
