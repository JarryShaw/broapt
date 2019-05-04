# -*- coding: utf-8 -*-

import contextlib
import glob
import json

import pefile

report = dict()
for pe in sorted(glob.glob('/dump/application/x-dosexec/*.exe')):
    with contextlib.suppress(pefile.PEFormatError):
        report[pe] = pefile.PE(pe).dump_dict()

with open('/var/log/bro/pe_report.json', 'w') as file:
    json.dump(report, file, indent=2,
              default=lambda obj: {'_repr_': repr(obj),
                                   '_type_': type(obj).__name__})
