.. module:: broapt.app.remote

----------------
Remote Detection
----------------

:File location:

   * Bundled implementation: ``source/client/python/scan.py``
   * Cluster implementation: ``cluster/app/source/python/remote.py``

Bundled Implementation
----------------------

.. function:: scan.remote(entry: Entry, mime: str, api: API)

   :availability: bundled implementation

   Request the BroAPT-Daemon server to perform *remote* detection.

   :param Entry entry: Extracted file to be processed.
   :param str mime: MIME type.
   :param API api: API entry from ``api.yml``.
   :return: Exit code (:data:`const.EXIT_SUCCESS` or :data:`const.EXIT_FAILURE`).
   :rtype: int

Cluster Implementation
----------------------

.. function:: remote.remote(entry: Entry, mime: str, api: API)

   :availability: cluster implementation

   .. seealso:: :func:`scan.remote`
