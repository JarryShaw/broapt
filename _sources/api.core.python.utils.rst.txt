-----------------------
Auxiliaries & Utilities
-----------------------

:File location:

   * Bundled implementation: ``source/client/python/utils.py``
   * Cluster implementation: ``cluster/core/source/python/utils.py``

.. decorator:: utils.suppress

   A decorator that suppresses all exceptions.

.. function:: utils.file_lock(file: str)

   A `context`_ lock for file modification with a file system lock.

   :param str file: Filename to be locked in the context.

   .. _context: https://docs.python.org/3/library/contextlib.html#contextlib.contextmanager

.. function:: utils.print_file(s: Any, file: str)

   Wrapper function to *process*-safely print ``s`` into ``file``.

   :param str s: Content to be printed.
   :param str file: Filename of output stream.

.. function:: utils.redirect(src: str, dst: str, label='unknown')

   Redirect the content of ``src`` to ``dst`` with ``label`` as prefix::

      <label> line from src

   :param str src: Filename of source file.
   :param str dst: Filename of destination file.
   :param str label: Optional prefix to the redirected content.

.. function:: utils.is_nan(value: Any)

   Check if ``value`` is ``None`` or a |NaN|_.

   .. |NaN| replace:: ``NaN``
   .. _NaN: https://docs.python.org/3/library/math.html#math.isnan

   :param value: Value to be checked.
   :rtype: bool
