-----------------------
Auxiliaries & Utilities
-----------------------

:File location:

   * Bundled implementation: ``source/server/python/util.py``
   * Cluster implementation: ``cluster/daemon/python/util.py``

.. decorator:: utils.suppress

   A decorator that suppresses all exceptions.

.. function:: utils.file_lock(file: str)

   A `context`_ lock for file modification with a file system lock.

   :param str file: Filename to be locked in the context.

.. function:: utils.print_file(s: Any, file: str)

   Wrapper function to *process*-safely print ``s`` into ``file``.

   :param str s: Content to be printed.
   :param str file: Filename of output stream.

.. function:: utils.temp_env(env: Dict[str, Any])

   A `context`_ for temporarily change the current |os.environ|_.

   :param env: Environment variables.
   :type env: Dict[str, Any]

   .. |os.environ| replace:: ``os.environ``
   .. _os.environ: https://docs.python.org/3/library/os.html#os.environ

.. _context: https://docs.python.org/3/library/contextlib.html#contextlib.contextmanager
