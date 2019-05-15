# -*- coding: utf-8 -*-
# pylint: disable=all

###############################################################################
# site customisation
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
###############################################################################

from http_parser import generate

# hook list
HOOK = [
    generate,
]
