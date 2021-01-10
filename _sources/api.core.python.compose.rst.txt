-------------------
Bro Script Composer
-------------------

:File location:

   * Bundled implementation: ``source/client/python/compose.py``
   * Cluster implementation: ``cluster/core/source/python/compose.py``

.. note::

   This file works as a standalone script for generating Bro scripts.
   It is **NOT** meant to be an *importable* module of the BroAPT system.

Introduction
------------

As we can config what MIME types to extract through the :envvar:`BROAPT_LOAD_MIME`
environment variable, the BroAPT-Core framework will automatically generate the
Bro scripts based on this environment variable and many others.

For MIME types with a *shell*-like pattern, we will use |fnmatch.translate|_
to convert the pattern into a regular expression.

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

Functions
---------

.. function:: compose.file_salt(uid: str)

   Update the ``config.bro`` (:doc:`api.core.bro.config`) with provided ``uid``
   as ``file_salt``.

.. function:: compose.compose()

   Compose Bro scripts with environment variables defined.

   .. note:: This function is the module entry.

.. function:: compose.escape(mime_type: str)

   Escape *shell*-like ``mime_type`` pattern to regular expression.

   .. caution::

      The underlying implementation of |fnmatch.translate|_ calls |re.escape|_
      to escape special characters. However, in Python 3.6, the function will
      escape all characters other than ASCIIs, numbers and underlines (``_``);
      whilst in Python 3.7, it will only escape characters defined in
      :data:`re._special_chars_map`.

      .. |fnmatch.translate| replace:: :func:`fnmatch.translate`
      .. _fnmatch.translate: https://docs.python.org/3/library/fnmatch.html#fnmatch.translate

      .. |re.escape| replace:: :func:`re.escape`
      .. _re.escape: https://docs.python.org/3/library/re.html#re.escape

Constants
---------

Auxiliaries
~~~~~~~~~~~

.. data:: compose.ROOT

   :type: ``str``

   Path to the BroAPT-Core framework source codes (absolute path at runtime).

.. data:: compose.BOOLEAN_STATES
   :value: {'1': True,    '0': False,
            'yes': True,  'no': False,
            'true': True, 'false': False,
            'on': True,   'off': False}

   Mapping of boolean states, c.f. |configparser|_.

   .. |configparser| replace:: ``configparser``
   .. _configparser: https://docs.python.org/3/library/configparser.html

Bro Configs
~~~~~~~~~~~

.. data:: compose.LOGS_PATH

   :type: ``str`` (path)
   :environ: :envvar:`BROAPT_LOGS_PATH`

   Path to system logs.

.. data:: compose.PCAP_PATH

   :type: ``str`` (path)
   :environ: :envvar:`BROAPT_PCAP_PATH`

   Path to source PCAP files.

.. data:: compose.MIME_MODE

   :type: ``bool``
   :environ: :envvar:`BROAPT_MIME_MODE`

   If group extracted files by MIME type.

.. data:: compose.HASH_MODE_MD5

   :type: ``bool``
   :environ: :envvar:`BROAPT_HASH_MD5`

   Calculate MD5 hash of extracted files.

.. data:: compose.HASH_MODE_SHA1

   :type: ``bool``
   :environ: :envvar:`BROAPT_HASH_SHA1`

   Calculate SHA1 hash of extracted files.

.. data:: compose.HASH_MODE_SHA256

   :type: ``bool``
   :environ: :envvar:`BROAPT_HASH_SHA256`

   Calculate SHA256 hash of extracted files.

.. data:: compose.X509_MODE

   :type: ``bool``
   :environ: :envvar:`BROAPT_X509_MODE`

   Include X509 information when running Bro.

.. data:: compose.ENTROPY_MODE

   :type: ``bool``
   :environ: :envvar:`BROAPT_ENTROPY_MODE`

   Include file entropy information when running Bro.

.. data:: compose.DUMP_PATH

   :type: ``str`` (path)
   :environ: :envvar:`BROAPT_DUMP_PATH`

   Path to extracted files.

. data:: compose.FILE_BUFFER

   :type: ``int`` (``uint64``)
   :environ: :envvar:`BROAPT_FILE_BUFFER`

   Reassembly buffer size for file extraction.

.. data:: compose.SIZE_LIMIT

   :type: ``int`` (``uint64``)
   :environ: :envvar:`BROAPT_SIZE_LIMIT`

   Size limit of extracted files.

.. data:: compose.JSON_MODE

   :type: ``bool``
   :environ: :envvar:`BROAPT_JSON_MODE`

   Toggle Bro logs in JSON or ASCII format.

.. data:: compose.LOAD_MIME

   :type: ``List[str]`` (*case-insensitive*)
   :environ: :envvar:`BROAPT_LOAD_MIME`

   A ``,`` or ``;`` separated string of MIME types to be extracted.

.. data:: compose.LOAD_PROTOCOL

   :type: ``List[str]`` (*case-insensitive*)
   :environ: :envvar:`BROAPT_LOAD_PROTOCOL`

   A ``,`` or ``;`` separated string of application layer protocols to be extracted,
   can be any of ``dtls``, ``ftp``, ``http``, ``irc`` and ``smtp``.

Subsitute Patterns
~~~~~~~~~~~~~~~~~~

.. data:: compose.FILE_TEMP

   :type: ``Tuple[str]``

   Template for MIME type extraction Bro scripts.

.. data:: compose.MIME_REGEX

   :type: ``re.Pattern``

   Pattern for ``mime`` (:data:`~compose.MIME_MODE`).

.. data:: compose.LOGS_REGEX

   :type: ``re.Pattern``

   Pattern for ``logs`` (:data:`~compose.LOGS_PATH`).

.. data:: compose.HASH_REGEX_MD5

   :type: ``re.Pattern``

   Pattern for ``md5`` (:data:`~compose.HASH_MODE_MD5`).

.. data:: compose.HASH_REGEX_SHA1

   :type: ``re.Pattern``

   Pattern for ``sha1`` (:data:`~compose.HASH_MODE_SHA1`).

.. data:: compose.HASH_REGEX_SHA256

   :type: ``re.Pattern``

   Pattern for ``sha256`` (:data:`~compose.HASH_MODE_SHA256`).

.. data:: compose.X509_REGEX

   :type: ``re.Pattern``

   Pattern for ``x509`` (:data:`~compose.X509_MODE`).

.. data:: compose.ENTR_REGEX

   :type: ``re.Pattern``

   Pattern for ``entropy`` (:data:`~compose.ENTROPY_MODE`).

.. data:: compose.JSON_REGEX

   :type: ``re.Pattern``

   Pattern for ``use_json`` (:data:`~compose.JSON_MODE`).

.. data:: compose.SALT_REGEX

   :type: ``re.Pattern``

   Pattern for ``file_salt`` (:func:`~compsoe.file_salt`).

.. data:: compose.FILE_REGEX

   :type: ``re.Pattern``

   Pattern for ``file_buffer`` (:data:`~compose.FILE_BUFFER`).

.. data:: compose.PATH_REGEX

   :type: ``re.Pattern``

   Pattern for ``path_prefix`` (:data:`~compose.DUMP_PATH`).

.. data:: compose.SIZE_REGEX

   :type: ``re.Pattern``

   Pattern for ``size_limit`` (:data:`~compose.SIZE_LIMIT`).

.. data:: compose.LOAD_REGEX

   :type: ``re.Pattern``

   Pattern for ``@load`` loading scripts.
