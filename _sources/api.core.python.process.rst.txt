------------------
Extraction Process
------------------

:File location:

   * Bundled implementation: ``source/client/python/process.py``
   * Cluster implementation: ``cluster/core/source/python/process.py``

.. function:: process.process(file: str)

   Process PCAP file with Bro IDS and put the root folder to Bro
   logs into :data:`const.QUEUE_LOGS`.

   :param str file: Path to PCAP file.

.. function:: communicate(log_root: str)

   Check if extracted files exist based on ``extracted`` field from
   the ``files.log``.

   In **bundled implementation**, then put the files into
   :data:`const.QUEUE_DUMP`.

   :param str log_root: Root folder to Bro logs.
   :raises ExtractWarning: When supposedly extracted file not found.

.. data:: process.SALT_LOCK
   :type: multiprocessing.Lock

   Lock for updating ``config.bro`` with :func:`compsoe.file_salt`.

.. data:: process.STDOUT_LOCK
   :type: multiprocessing.Lock

   Lock for writing to the ``stdout`` *replica* :data:`const.STDOUT`.

.. data:: process.STDERR_LOCK
   :type: multiprocessing.Lock

   Lock for writing to the ``stderr`` *replica* :data:`const.STDERR`.

.. exception:: process.ExtractWarning

   :bases: :exc:`Warning`

   Extraction warning.
