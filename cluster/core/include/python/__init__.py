# -*- coding: utf-8 -*-
# pylint: disable=all

###############################################################################
# site customisation
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
###############################################################################

import multiprocessing

from const import HOOK_CPU
from http_parser import generate

# hook list
HOOK = [generate]


def wrapper(args):
    func, log_name = args
    return func(log_name)


def hook(log_name):
    if HOOK_CPU <= 1:
        [func(log_name) for func in HOOK]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(HOOK_CPU).map(wrapper, map(lambda func: (func, log_name), HOOK))
