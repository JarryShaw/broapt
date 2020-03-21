====================
BroAPT-App Framework
====================

The BroAPT-App framework is the analysis framework for the BroAPT
system. For more information about the framework, please refer to previous
documentation at :doc:`broapt-app`.

Python Modules
==============

.. toctree::
   :maxdepth: 4

   api.app.python.__init__
   api.app.python.__main__
   api.app.python.cfgparser
   api.app.python.const
   api.app.python.process
   api.app.python.remote
   api.app.python.utils

API Configurations
==================

:File location:

   * Bundled implementation: ``source/include/api/``
   * Cluster implementation: ``cluster/app/include/api/``

As discussed in previous documentation, we provided a YAML configuration file
``api.yml`` for registering MIME type specific detection methods.

For example, following is the requirements of an API for analysing PDF files
(MIME type: ``application/pdf``):

- Root: ``/api/``
- Target:
  - MIME type: ``application/pdf``
  - file name: ``/dump/application/pdf/test.pdf``
- API:
  - working directory: ``./pdf_analysis``
  - environment: ``ENV_FOO=1``, ``ENV_BAR=this is an environment variable``

The configuration section should then be:

.. code:: yaml

   application:
     ...  # other APIs
     pdf:
       remote: false
       workdir: pdf_analysis
       environ:
         ENV_FOO: 1
         ENV_BAR: this is an environment variable
       install:
         - apt-get update
         - apt-get install -y python python-pip
         - python -m pip install -r requirements.txt
         - rm -rf /var/lib/apt/lists/*
         - apt-get remove -y --auto-remove python-pip
         - apt-get clean
       scripts:
         - ${PYTHON27} detect.py [...]                # refer to /usr/bin/python
         - ...                                        # and some random command
       report: ${PYTHON27} report.py                  # generate final report

.. important::

   ``report`` section is **MANDATORY**.

   If ``remote`` is ``true``, then the BroAPT-APP framework will run the
   corresponding API in the host machine through the BroAPT-Daemon server.

The BroAPT-App framework will work as following:

1. set the following environment variables:

   * per target file

     - ``BROAPT_PATH="/dump/application/pdf/test.pdf"``
     - ``BROAPT_MIME="application/pdf"``

   * per API configuration

     - ``ENV_FOO=1``
     - ``ENV_BAR="this is an environment variable"``

2. change the current working directory to
   ``/api/application/pdf/pdf_analysis``

3. if run for the first time, run the following commands:

   - ``apt-get update``
   - ``apt-get install -y python python-pip``
   - ``python -m pip install -r requirements.txt``
   - ``rm -rf /var/lib/apt/lists/*``
   - ``apt-get remove -y --auto-remove python-pip``
   - ``apt-get clean``

4. run the following mid-stage commands:

   - ``/usr/bin/python detect.py [...]``
   - ...

5. generate final report:
   ``/usr/bin/python report.py``

.. note::

   The registered MIME types support *shell*-like patterns.

   If the API of a specific MIME type is not provided, it will then fallback
   to the API configuration registered under the special ``example`` MIME type.

.. raw:: html

   <details>
     <summary>Content of <code class="docutils literal notranslate"><span class="pre">api.yml</span></code> (bundled implementation)</summary>

.. literalinclude:: ../../../source/include/api/api.yml
   :language: yaml

.. raw:: html

   </details>

.. raw:: html

   <details>
     <summary>Content of <code class="docutils literal notranslate"><span class="pre">api.yml</span></code> (cluster implementation)</summary>

.. literalinclude:: ../../../cluster/app/include/api/api.yml
   :language: yaml

.. raw:: html

   </details>

.. caution::

   For bundled implementation, the runtime of *local* APIs are in the CentOS 7
   Docker container.

   For cluster implementation, the runtime of *local* APIs are in the Ubuntu 16.04
   Docker container.

Wrapper Scripts
===============

For the Docker container, we have created some Shell/Bash wrapper scripts to
make the life a little bit better.

----------------------
Bundled Implementation
----------------------

:File location: ``source/client/init.sh``

As the BroAPT-App framework is already integrated into the source codes, there's
no need to another wrapper script to start the BroAPT-App framework. It shall be
run directly after the BroAPT-Core framework.

.. literalinclude:: ../../../source/client/init.sh
   :language: shell

----------------------
Cluster Implementation
----------------------

:File location: ``cluster/app/source/init.sh``

.. literalinclude:: ../../../cluster/app/source/init.sh
   :language: shell
