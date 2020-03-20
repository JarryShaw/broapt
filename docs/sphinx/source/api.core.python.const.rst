----------------
Common Constants
----------------

:File location:

   * Bundled implementation: ``source/client/python/const.py``
   * Cluster implementation: ``cluster/core/source/python/const.py``

.. data:: const.ROOT

   :type: ``str``

   Path to the BroAPT-Core framework source codes (absolute path at runtime).

.. data:: const.BOOLEAN_STATES
   :value: {'1': True,    '0': False,
            'yes': True,  'no': False,
            'true': True, 'false': False,
            'on': True,   'off': False}

   Mapping of boolean states, c.f. |configparser|_.

   .. |configparser| replace:: ``configparser``
   .. _configparser: https://docs.python.org/3/library/configparser.html

.. data:: const.CPU_CNT

   :type: ``int``
   :environ: :envvar:`BROAPT_CPU`

   Number of BroAPT concurrent processes for PCAP analysis. If not provided, then the
   number of system CPUs will be used.

.. data:: const.INTERVAL

   :type: ``float``
   :environ: :envvar:`BROAPT_INTERVAL`

   Wait interval after processing current pool of PCAP files.

.. data:: const.DUMP_PATH

   :type: ``str`` (path)
   :environ: :envvar:`BROAPT_DUMP_PATH`

   Path to extracted files.

.. data:: const.PCAP_PATH

   :type: ``str`` (path)
   :environ: :envvar:`BROAPT_PCAP_PATH`

   Path to source PCAP files.

.. data:: const.LOGS_PATH

   :type: ``str`` (path)
   :environ: :envvar:`BROAPT_LOGS_PATH`

   Path to system logs.

.. data:: const.MIME_MODE

   :type: ``bool``
   :environ: :envvar:`BROAPT_MIME_MODE`

   If group extracted files by MIME type.

.. data:: const.BARE_MODE

   :type: ``bool``
   :environ: :envvar:`BROAPT_BARE_MODE`

   Run Bro in bare mode (don't load scripts from the ``base/`` directory).

.. data:: const.NO_CHKSUM

   :type: ``bool``
   :environ: :envvar:`BROAPT_NO_CHKSUM`

   Ignore checksums of packets in PCAP files when running Bro.

.. data:: const.HOOK_CPU

   :type: ``int``
   :environ: :envvar:`BROAPT_HOOK_CPU`

   Number of BroAPT concurrent processes for Python hooks.

.. data:: const.FILE

   :type: ``str``

   Path to file system database of processed PCAP files.

.. data:: const.TIME

   :type: ``str``

   Path to log file of processing time records.

.. data:: const.STDOUT

   :type: ``str``

   Path to ``stdout`` *replica*.

.. data:: const.STDERR

   :type: ``str``

   Path to ``stderr`` *replica*.

.. data:: const.QUEUE

   :type: ``multiprocessing.Queue``

   In **cluster implementation**, teleprocess communication queue
   for log processing.

.. data:: const.QUEUE_LOGS

   :type: ``multiprocessing.Queue``

   In **bundled implementation**, teleprocess communication queue
   for log processing.
