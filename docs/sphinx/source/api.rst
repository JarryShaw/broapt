=============
API Reference
=============

As discussed previously, the BroAPT system has two different implementation
architectures. They are similar in overall concepts and processing, but may
various in underlying internal source codes. We'll try to break down into
details of each implementation for you to develop new extensions, hooks,
scripts for the BroAPT system in *humans* way.

.. toctree::
   :maxdepth: 3

   api.core
   api.app
   api.daemon
   api.misc

--------------
System Runtime
--------------

The whole BroAPT folder in the Docker container (**of bundled implementation**)
at runtime would be like::

   # project root
   /broapt/
   │   # entrypoint wrapper script
   ├── init.sh
   │   # Python source codes
   ├── python
   │   │   # setup PYTHONPATH
   │   ├── __init__.py
   │   │   # entry point
   │   ├── __main__.py
   │   │   # config parser
   │   ├── cfgparser.py
   │   │   # Bro script composer
   │   ├── compose.py
   │   │   # global constants
   │   ├── const.py
   │   │   # Bro log parser
   │   ├── logparser.py
   │   │   # BroAPT-Core logic
   │   ├── process.py
   │   │   # multiprocessing support
   │   ├── remote.py
   │   │   # BroAPT-App logic
   │   ├── scan.py
   │   │   # Python hooks
   │   ├── sites
   │   │   │   # register hooks
   │   │   ├── __init__.py
   │   │   └── ...
   │   │   # utility functions
   │   └── utils.py
   │   # Bro source scripts
   └── scripts
       │   # load FileExtraction module
       ├── __load__.bro
       │   # configurations
       ├── config.bro
       │   # MIME-extension mappings
       ├── file-extensions.bro
       │   # protocol hooks
       ├── hooks/
       │   │   # extract DTLS
       │   ├── extract-dtls.bro
       │   │   # extract FTP_DATA
       │   ├── extract-ftp.bro
       │   │   # extract HTTP
       │   ├── extract-http.bro
       │   │   # extract IRC_DATA
       │   ├── extract-irc.bro
       │   │   # extract SMTP
       │   └── extract-smtp.bro
       │   # core logic
       ├── main.bro
       │   # MIME hooks
       │── plugins/
       │   │   # extract all files
       │   ├── extract-all-files.bro
       │   │   # extract by BRO_MIME
       │   ├── extract-white-list.bro
       │   │   # generated scripts by BRO_MIME
       │   └── ...
       │   # site functions by user
       └── sites/
           │   # load site functions
           ├── __load__.bro
           └── ...

where ``/broapt/python/sites`` is the path for custom Python hooks and
``/broapt/scripts/sites/`` is the path for custom Bro scripts.

And most importantly, the very entrypoint for the whole BroAPT system
is as following:

.. code:: shell

   #!/usr/bin/env bash

   set -aex

   # change curdir
   cd /broapt

   # load environs
   if [ -f .env ] ; then
       source .env
   fi

   # compose Bro scripts
   /usr/bin/python3.6 python/compose.py

   # run scripts
   /usr/bin/python3.6 python $@

   # sleep
   sleep infinity

0. The script will first change the current working directory to the root
   path ``/broapt/``.
1. If there is a ``.env`` *dotenv* file for environment variables configuration,
   it will be loaded and saved into current runtime scope (``set -a``).
2. Generate Bro scripts based on environment variables.
3. Start the main application, i.e. BroAPT-Core and BroAPT-App frameworks.

---------------
Developer Notes
---------------

Since the BroAPT system was not intended for packaging and distribution,
we didn't provide a ``setup.py`` to wrap everything as a ``broapt`` module.
However, in a quite *hacky* way, we injected the ``sys.path`` import path,
so that we can directly import the files as if they're at top levels.

As you can see in the ``/broapt/python/sites/__init__.py``, i.e. the
*module* entry of Python hooks is as following:

.. code-block:: python
   :emphasize-lines: 9,10

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

where ``extracted_files`` refers to ``/broapt/python/sites/extracted_files.py``
and ``http_parser`` refers to ``/broapt/python/sites/http_parser.py``.

You may have noticed the lines in *site customisation* modified the ``sys.path``
import path so that we don't need to worry about importing stuff from the BroAPT
Python source codes.

If you wish to use auxiliary functions and module constants from the main
application, then you can still import them as if from the top level:

.. code:: python

   # path to logs from module constants
   from const import LOGS_PATH
   # Bro log parsing utilities
   from logparser import parse
   # auxiliary functions for BroAPT
   from utils import is_nan, print_file
