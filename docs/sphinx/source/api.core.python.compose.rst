-------------------
Bro Script Composer
-------------------

:File location:

   * Bundled implementation: ``source/client/python/compose.py``
   * Cluster implementation: ``cluster/core/source/python/compose.py``

.. note::

   This file works as a standalone script for generating Bro scripts.
   It is **NOT** a *importable* module of the BroAPT system.

As we can config what MIME types to extract through the :envvar:`BROAPT_LOAD_MIME`
environment variable, the BroAPT-Core framework will automatically generate the
Bro scripts based on this environment variable and many others.

For MIME types with a *shell*-like pattern, we will use |fnmatch.translate|_
to convert the pattern into a regular expression.

.. |fnmatch.translate| replace:: :func:`fnmatch.translate`
.. _fnmatch.translate: https://docs.python.org/3/library/fnmatch.html#fnmatch.translate

.. warning::

   The underlying implementation of |fnmatch.translate|_ calls |re.escape|_
   to escape special characters. However, in Python 3.6, the function will
   escape all characters other than ASCIIs, numbers and underlines (``_``);
   whilst in Python 3.7, it will only escape characters defined in
   :data:`re._special_chars_map`.

.. |re.escape| replace:: :func:`re.escape`
.. _re.escape: https://docs.python.org/3/library/re.html#re.escape

A generated :doc:`Bro script <api.core.bro.file-extensions>` for ``hook`` function
extracting files with MIME type ``example/test-*`` would be as following:

.. code:: zeek

   @load ../__load__.bro

   module FileExtraction;

   hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5 {
       if ( meta?$mime_type && /example\/test\-.*/ == meta$mime_type )
           break;
   }

Besides this, the Bro script composer will also generate/rewrite the
:doc:`Bro configurations <api.core.bro.config>` to customise several
metrics and to load the scripts as specified in the environment variables.

.. note::

   The full list of supported environment variables is as following:

   * :envvar:`BROAPT_LOGS_PATH`
   * :envvar:`BROAPT_PCAP_PATH`
   * :envvar:`BROAPT_MIME_MODE`
   * :envvar:`BROAPT_HASH_MD5`
   * :envvar:`BROAPT_HASH_SHA1`
   * :envvar:`BROAPT_HASH_SHA256`
   * :envvar:`BROAPT_X509_MODE`
   * :envvar:`BROAPT_ENTROPY_MODE`
   * :envvar:`BROAPT_DUMP_PATH`
   * :envvar:`BROAPT_FILE_BUFFER`
   * :envvar:`BROAPT_SIZE_LIMIT`
   * :envvar:`BROAPT_JSON_MODE`
   * :envvar:`BROAPT_LOAD_MIME`
   * :envvar:`BROAPT_LOAD_PROTOCOL`
