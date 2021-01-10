----------------
Common Constants
----------------

:File location:

   * Bundled implementation: ``source/client/python/const.py``
   * Cluster implementation: ``cluster/app/source/python/const.py``

.. data:: const.ROOT

   :type: ``str``

   Path to the BroAPT-App framework source codes (absolute path at runtime).

.. data:: const.CPU_CNT

   :type: ``int``
   :environ:
      * Bundled implementation: :envvar:`BROAPT_SCAN_CPU`
      * Cluster implementation: :envvar:`BROAPT_APP_CPU`

   Number of BroAPT concurrent processes for extracted file analysis. If not provided, then the
   number of system CPUs will be used.

.. data:: const.INTERVAL

   :type: ``int``
   :environ:
      * Bundled implementation: :envvar:`BROAPT_INTERVAL`
      * Cluster implementation: :envvar:`BROAPT_APP_INTERVAL`

   Wait interval after processing current pool of extracted files.

.. data:: const.MAX_RETRY

   :type: ``int``

   Retry times for failed commands.

.. data:: const.EXIT_SUCCESS
   :value: 0

   :type: ``int``

   Exit code upon success.

.. data:: const.EXIT_FAILURE
   :value: 1

   :type: ``int``

   Exit code upon failure.

.. data:: const.LOGS_PATH

   :type: ``str``
   :environ: :envvar:`BROAPT_LOGS_PATH`

   Path to system logs.

.. data:: const.DUMP_PATH

   :type: ``str``
   :environ: :envvar:`BROAPT_DUMP_PATH`

   Path to extracted files.

.. data:: const.API_ROOT

   :type: ``str``
   :environ: :envvar:`BROAPT_API_ROOT`

   Path to the API root folder.

.. data:: const.API_LOGS

   :type: ``str``
   :environ: :envvar:`BROAPT_API_LOGS`

   Path to API detection logs.

.. data:: const.API_DICT

   :type: ``Dict[str, cfgparser.API]``

   Database for API entries.

   .. seealso:: ``cfgparser.parse``

.. data:: const.SERVER_NAME_HOST

   :type: ``str``
   :environ: :envvar:`BROAPT_NAME_HOST`

   Hostname of BroAPT-Daemon server.

.. data:: const.SERVER_NAME_PORT

   :type: ``str``
   :environ: :envvar:`BROAPT_NAME_PORT`

   Port number of BroAPT-Daemon server.

.. data:: const.SERVER_NAME

   :type: ``str``

   .. code:: python

      f'http://{SERVER_NAME_HOST}:{SERVER_NAME_PORT}/api/v1.0/scan'

   URL for BroAPT-Daemon server's scanning API.

.. data:: const.DUMP

   :type: ``str``

   .. code:: python

      os.path.join(LOGS_PATH, 'dump.log')

   Path to file system database of processed extracted files.

.. data:: const.FAIL

   :type: ``str``

   .. code:: python

      os.path.join(LOGS_PATH, 'fail.log')

   Path to file system database of failed processing extracted files.

.. data:: const.FILE_REGEX

   :type: ``re.Pattern``
   :availability: bundled implementation

   .. code:: python

      re.compile(r'''
          # protocol prefix
          (?P<protocol>DTLS|FTP_DATA|HTTP|IRC_DATA|SMTP|\S+)
          -
          # file UID
          (?P<fuid>F\w+)
          \.
          # PCAP source
          (?P<pcap>.+?)
          \.
          # media-type
          (?P<media_type>application|audio|example|font|image|message|model|multipart|text|video|\S+)
          \.
          # subtype
          (?P<subtype>\S+)
          \.
          # file extension
          (?P<extension>\S+)
      ''', re.IGNORECASE | re.VERBOSE)

   Regular expression to match and fetch information from extracted files.

   .. seealso:: :data:`__main__.FILE_REGEX`

.. data:: const.MIME_REGEX

   :type: ``re.Pattern``
   :availability: bundled implementation

   .. code:: python

      re.compile(r'''
          # media-type
          (?P<media_type>application|audio|example|font|image|message|model|multipart|text|video|\S+)
          /
          # subtype
          (?P<subtype>\S+)
      ''', re.VERBOSE | re.IGNORECASE)

   Regular expression to match and fetch information from MIME type.

.. data:: const.QUEUE_DUMP

   :type: ``multiprocessing.Queue``
   :availability: bundled implementation

   Teleprocess communication queue for extracted files processing.
