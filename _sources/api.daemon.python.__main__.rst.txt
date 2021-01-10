-----------------
System Entrypoint
-----------------

:File location:

   * Bundled implementation: ``source/server/python/__main__.py``
   * Cluster implementation: ``cluster/daemon/python/__main__.py``

This file wraps the whole system and make the ``python`` folder callable
as a module where the ``__main__.py`` will be considered as the entrypoint.

.. function:: run()

   Start the `Flask`_ application and Docker watchdog.

.. _Flask: https://flask.palletsprojects.com
