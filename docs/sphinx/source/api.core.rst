=====================
BroAPT-Core Framework
=====================

The BroAPT-Core framework is the extraction framework for the BroAPT
system. For more information about the framework, please refer to previous
documentation at :doc:`broapt-core`.

Bro Scripts
===========

.. toctree::
   :maxdepth: 4

   api.core.bro.__load__
   api.core.bro.config
   api.core.bro.file-extensions
   api.core.bro.main
   api.core.bro.hooks
   api.core.bro.plugins
   api.core.bro.sites

Python Modules
==============

.. toctree::
   :maxdepth: 4

   api.core.python.__init__
   api.core.python.__main__
   api.core.python.compose
   api.core.python.const
   api.core.python.logparser
   api.core.python.process
   api.core.python.remote
   api.core.python.utils
   api.core.python.sites

Wrapper Scripts
===============

For the Docker container, we have created some Shell/Bash wrapper scripts to
make the life a little bit better.

----------------------
Bundled Implementation
----------------------

:File location: ``/source/client/init.sh``

.. literalinclude:: ../../../source/client/init.sh
   :language: shell

----------------------
Cluster Implementation
----------------------

:File location: ``/cluster/core/source/init.sh``

.. literalinclude:: ../../../cluster/core/source/init.sh
   :language: shell
