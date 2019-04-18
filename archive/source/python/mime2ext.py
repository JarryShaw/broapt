# -*- coding: utf-8 -*-

import mimetypes
import sys


def init_table():
    mimetypes.init()
    common, mime2ext = mimetypes._db.types_map_inv  # pylint: disable=protected-access
    mime2ext.update(common)
    return mime2ext


def guess_extension():
    try:
        mime = sys.argv[1]
        db = init_table()
        ext = db.get(mime)
        if ext is None:
            return 1
        print(ext[0][1:])
    except ValueError:
        print('usage: mime2ext <mime>', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(guess_extension())
