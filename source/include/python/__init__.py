# -*- coding: utf-8 -*-
# pylint: disable=all

###############################################################################
# site customisation
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
###############################################################################

from extracted_files import generate_log as info_log
from http_parser import generate as http_log, close as http_log_exit

# log analysis hook list
HOOK = [
    http_log,
    info_log,
]

# exit hooks
EXIT = [
    http_log_exit,
]
