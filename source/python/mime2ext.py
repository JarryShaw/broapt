# -*- coding: utf-8 -*-

import mimetypes


def generate_table():
    mimetypes.init()
    common, mime2ext = mimetypes._db.types_map_inv  # pylint: disable=protected-access
    mime2ext.update(common)
