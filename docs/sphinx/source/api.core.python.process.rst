----------------------
Main (PCAP) Processing
----------------------

:File location:

   * Bundled implementation: ``source/client/python/process.py``
   * Cluster implementation: ``cluster/core/source/python/process.py``

Functions
---------

.. function:: process(file: str)

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

Constants
---------

.. data:: SALT_LOCK
   :type: multiprocessing.Lock

   Lock for updating ``config.bro`` with :func:`compsoe.file_salt`.

.. data:: STDOUT_LOCK
   :type: multiprocessing.Lock

   Lock for writing to the ``stdout`` *replica* :data:`const.STDOUT`.

.. data:: STDERR_LOCK
   :type: multiprocessing.Lock

   Lock for writing to the ``stderr`` *replica* :data:`const.STDERR`.

Warnings
--------

.. exception:: ExtractWarning

   Extraction warning.
