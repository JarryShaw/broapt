---------------
Docker Watchdog
---------------

:File location:

   * Bundled implementation: ``source/server/python/compose.py``
   * Cluster implementation: ``cluster/daemon/python/compose.py``

This module provides a handy way to always keep the underlying
BroAPT system in Docker containers running.

.. function:: compose.docker_compose()

   A `context`_ to manager Docker containers. This function will start
   :func:`~compose.watch_container` as a background process.

   .. note::

      When start, the function will start the Docker containers through
      :func:`~compose.start_container`.

      Before exit, the function will toggle the value of
      :data:`~compose.UP_FLAG` to ``False`` and wait for the process
      to exit. And gracefully stop the Docker containers through
      :func:`~compose.stop_container`.

   .. _context: https://docs.python.org/3/library/contextlib.html#contextlib.contextmanager

.. function:: compose.watch_container()

   Supervise the status of Docker containers while the system is running,
   i.e. :data:`~compose.UP_FLAG` is ``True``.

   :raises ComposeWarning: If fail to poll status of Docker containers.

.. function:: compose.start_container()

   Start Docker container using Docker Compose in *detached* mode.

.. function:: compose.stop_container()

   Stop Docker container gracefully using Docker Compose, and clean up
   Docker caches.

.. function:: compose.flask_exit(signum: Optional[signal.Signals] = None, frame: Optional[types.FrameType] = None)

   `Flask`_ exit signal handler. This function is registered as handler
   for :data:`const.KILL_SIGNAL` through :func:`~compose.register`.

   .. _Flask: https://flask.palletsprojects.com

.. function:: compose.register()

   Register :func:`~compose.flask_exit` as signal handler of
   :data:`const.KILL_SIGNAL`.

.. data:: compose.UP_FLAG
   :value: multiprocessing.Value('B', True)

   If the BroAPT system is actively running.

.. exception:: compose.ComposeWarning

   :bases: Warning

   Warn if fail to poll status of Docker containers.
