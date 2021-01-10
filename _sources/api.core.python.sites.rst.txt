-------------------
Site Customisations
-------------------

:File location:

   * Bundled implementation: ``source/include/python/``
   * Cluster implementation: ``cluster/core/include/python/``

This folder will be mapped into the Docker container as ``/broapt/python/sites/``.
You may register your customised Python hooks in the ``__init__.py`` file.

.. data:: sites.HOOK
   :type: List[Callable[[str], Any]]

   Registry for *processing* hooks.

   Registered function should take the path to the folder of Bro logs as
   a single parameter, return values will be ignored. Such functions will
   be called on each Bro log folder generated from PCAP files.

.. data:: sites.EXIT
   :type: List[Callable[[], Any]]

   Registry for *closing* hooks.

   Registered function should take **NO** parameters, return values will
   be ignored. Such functions will be called before the system exits.

Currently, we have integrated two sets of customised Python hooks, please see
:doc:`broapt-core` for more information.
