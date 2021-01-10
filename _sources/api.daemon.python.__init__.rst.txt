------------
Module Entry
------------

:File location:

   * Bundled implementation: ``source/server/python/__init__.py``
   * Cluster implementation: ``cluster/daemon/python/__init__.py``

This file merely modifies the |sys.path|_ so that we can import the Python modules
as if from the top level.

.. |sys.path| replace:: :data:`sys.path`
.. _sys.path: https://docs.python.org/3/library/sys.html#sys.path
