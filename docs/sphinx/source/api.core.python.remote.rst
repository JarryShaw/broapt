-------------------
Bro Logs Processing
-------------------

:File location:

   * Bundled implementation: ``source/client/python/remote.py``
   * Cluster implementation: ``cluster/core/source/python/remote.py``

Hook Mainloop
-------------

.. function:: remote.remote_proc()

   A `context`_ for running Python hooks at the background.
   This function starts :func:`~remote.remote` as a new process.

   .. note::

      Before exit, it will send ``SIGUSR1`` signal to the background
      process and wait for the process to exit.

   .. _context: https://docs.python.org/3/library/contextlib.html#contextlib.contextmanager

.. function:: remote.remote()

   Runtime mainloop for Python hooks.

   The function will start as an *indefinite* loop to fetch path to Bro
   logs from :data:`const.QUEUE_LOGS`, and execute registered Python hooks
   on them.

   When :data:`~remote.JOIN` is set to ``True``, the function will break
   from the loop and execute registered Python hooks for *closing*
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

   Warns when Python hooks execution failed.

Signal Handling
---------------

.. function:: remote.json(*args, **kwargs)

   Toggle :data:`~remote.JOIN` to ``True``.

   .. note:: This function is registered as handler for ``SIGUSR1```.

.. data:: remote.JOIN
   :value: multiprocessing.Value('B', False)

   Flag to stop mainloop.
