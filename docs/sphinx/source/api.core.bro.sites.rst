-------------------
Site Customisations
-------------------

:File location:

   * Bundled implementation: ``source/include/scripts/``
   * Cluster implementation: ``cluster/core/include/scripts/``

This folder will be mapped into the Docker container as ``/broapt/scripts/sites/``.
You may load your customised script in the ``__load__.bro`` file.

.. note::

   Should the ``sites`` folder doesn't exist, it will not be loaded into the
   main scripts to avoid raising errors at runtime.

Currently, we have integrated six sets of customised Bro scripts, please see
:doc:`broapt-core` for more information.
