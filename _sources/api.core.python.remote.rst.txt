-------------------
Bro Logs Processing
-------------------

:File location:

   * Bundled implementation: ``source/client/python/remote.py``
   * Cluster implementation: ``cluster/core/source/python/remote.py``

Hook Mainloop
-------------

.. function:: remote.remote_proc()

   A `context`_ for running processes at the background.

   In **bundled implementation**, this function also starts both
   :func:`~remote.remote_dump` and :func:`~remote.remote_logs` as new
   processes.

   In **cluster implementation**, this function starts
   :func:`~remote.remote` as a new process.

   .. note::

      Before exit, in **bundled implementation**, it will send ``SIGUSR1``
      signal to the :func:`~remote.remote_dump` background process and
      ``SIGUSR2`` signal to the :func:`~remote.remote_logs` background
      process; then wait for the process to gracefully exit.

      In **cluster implementation**, it will send ``SIGUSR1`` signal to
      the :func:`~remote.remote_logs` background process and wait for the
      process to gracefully exit.

   .. _context: https://docs.python.org/3/library/contextlib.html#contextlib.contextmanager

.. function:: remote.remote_logs()

   :availability: bundled implementation

   Runtime mainloop for Python hooks.

   The function will start as an *indefinite* loop to fetch path to Bro
   logs from :data:`const.QUEUE_LOGS`, and execute registered Python hooks
   on them.

   When :data:`~remote.JOIN_LOGS` is set to ``True``, the function will
   break from the loop and execute registered Python hooks for *closing*
   (:data:`sites.EXIT`).

   :raises HookWarning: If hook execution failed.

.. function:: remote.remote()

   :availability: cluster implementation

   The function will start as an *indefinite* loop to fetch path to Bro
   logs from :data:`const.QUEUE`, and execute registered Python hooks
   on them.

   When :data:`~remote.JOIN` is set to ``True``, the function will
   break from the loop and execute registered Python hooks for *closing*
   (:data:`sites.EXIT`).

   :raises HookWarning: If hook execution failed.

.. function:: hook(log_name: str)

   Wrapper function for running registered Python hooks.

   :param str log_name: Root folder of Bro logs.

.. function:: wrapper_logs(args: Tuple[Callable[[str], Any], str])

   Wrapper function for running registered Python hooks for *processing*
   (:data:`sites.HOOK`).

.. function:: wrapper_func(func: Callable[[], Any])

   Wrapper function for running registered Python hooks for *closing*
   (:data:`sites.EXIT`).

Warnings
--------

.. exception:: remote.HookWarning

   :bases: :exc:`Warning`

   Warns when Python hooks execution failed.

Signal Handling
---------------

Bundled Implementation
~~~~~~~~~~~~~~~~~~~~~~

.. function:: remote.join_logs(*args, **kwargs)

   :availability: bundled implementation

   Toggle :data:`~remote.JOIN_LOGS` to ``True``.

   .. note:: This function is registered as handler for ``SIGUSR2```.

.. data:: remote.JOIN_LOGS
   :value: multiprocessing.Value('B', False)

   :availability: bundled implementation

   Flag to stop the :func:`~remote.remote_logs` background process.

Cluster Implementation
~~~~~~~~~~~~~~~~~~~~~~

.. function:: remote.join(*args, **kwargs)

   :availability: cluster implementation

   Toggle :data:`~remote.JOIN` to ``True``.

   .. note:: This function is registered as handler for ``SIGUSR1```.

.. data:: remote.JOIN
   :value: multiprocessing.Value('B', False)

   :availability: cluster implementation

   Flag to stop the :func:`~remote.remote` background process.
