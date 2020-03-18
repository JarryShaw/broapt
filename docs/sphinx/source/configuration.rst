==============
Configurations
==============

As discussed in previous sections, the BroAPT system is configurable
in various ways. You can configure the outer system from the entry CLI
of BroAPT-Daemon server, and the main framework through Docker Compose
environment variables.

BroAPT-Daemon Server
====================

Command Line Interface
----------------------

.. code:: text

   usage: broaptd [-h] [-v] [-e ENV] [-s SIGNAL] [-t HOST] [-p PORT]
                  [-f DOCKER_COMPOSE] [-d DUMP_PATH] [-l LOGS_PATH] [-r API_ROOT]
                  [-a API_LOGS] [-i INTERVAL] [-m MAX_RETRY]

   BroAPT Daemon

   optional arguments:
     -h, --help            show this help message and exit
     -v, --version         show program's version number and exit

   environment arguments:
     -e ENV, --env ENV     path to dotenv file
     -s SIGNAL, --signal SIGNAL
                           daemon kill signal

   server arguments:
     -t HOST, --host HOST  the hostname to listen on
     -p PORT, --port PORT  the port of the webserver

   compose arguments:
     -f DOCKER_COMPOSE, --docker-compose DOCKER_COMPOSE
                           path to BroAPT's compose file
     -d DUMP_PATH, --dump-path DUMP_PATH
                           path to extracted files
     -l LOGS_PATH, --logs-path LOGS_PATH
                           path to log files

   API arguments:
     -r API_ROOT, --api-root API_ROOT
                           path to detection APIs
     -a API_LOGS, --api-logs API_LOGS
                           path to API runtime logs

   runtime arguments:
     -i INTERVAL, --interval INTERVAL
                           sleep interval
     -m MAX_RETRY, --max-retry MAX_RETRY
                           command retry

Environment Variables
---------------------

As suggests in the ``--env`` option, you may provice a *dotenv* (``.env``) file
for the BroAPT-Daemon server to configure itself.

Acceptable environment variables are as following:

.. envvar:: BROAPT_KILL_SIGNAL

   :type: ``int``
   :default: ``15`` (``SIGTERM``)
   :CLI Option: ``-s`` / ``--signal``

   Daemon kill signal.

.. envvar:: BROAPT_SERVER_HOST

   :type: ``str`` (hostname)
   :default: ``0.0.0.0``
   :CLI Option: ``-t`` / ``--host``

   The hostname to listen on.

.. envvar:: BROAPT_SERVER_PORT

   :type: ``int`` (port number)
   :default: ``5000``
   :CLI Option: ``-p`` / ``--port``

   The port of the webserver.

.. envvar:: BROAPT_DOCKER_COMPOSE

   :type: ``str`` (path)
   :default: ``docker-compose.yml``
   :CLI Option: ``-f`` / ``--docker-compose``

   Path to BroAPT's compose file.

.. envvar:: BROAPT_DUMP_PATH

   :type: ``str`` (path)
   :default: ``None``
   :CLI Option: ``-d`` / ``--dump-path``

   Path to extracted files.

.. envvar:: BROAPT_LOGS_PATH

   :type: ``str`` (path)
   :default: ``None``
   :CLI Option: ``-l`` / ``--logs-path``

   Path to log files.

.. envvar:: BROAPT_API_ROOT

   :type: ``str`` (path)
   :default: ``None``
   :CLI Option: ``-r`` / ``--api-root``

   Path to detection APIs.

.. envvar:: BROAPT_API_LOGS

   :type: ``str`` (path)
   :default: ``None``
   :CLI Option: ``-a`` / ``--api-logs``

   Path to API runtime logs.

.. envvar:: BROAPT_INTERVAL

   :type: ``float``
   :default: ``10``
   :CLI Option: ``-i`` / ``--interval``

   Sleep interval.

.. envvar:: BROAPT_MAX_RETRY

   :type: ``int``
   :default: ``3``
   :CLI Option: ``-m`` / ``--max-retry``

   Command retry.

.. note::

   Environment variables of ``bool`` type will be translated through
   the following mapping table (**case-insensitive**):

   ======== =========
   ``True`` ``False``
   ======== =========
   ``1``    ``0``
   ``yes``  ``no``
   ``true`` ``false``
   ``on``   ``off``
   ======== =========

BroAPT-Core Framework
=====================

The BroAPT-Core framework only supports configuration through environment variables.

.. envvar:: BROAPT_CPU

   :type: ``int``
   :default: ``None``

   Number of BroAPT concurrent processes for PCAP analysis. If not provided, then the
   number of system CPUs will be used.

.. envvar:: BROAPT_INTERVAL

   :type: ``float``
   :default: ``10``

   Wait interval after processing current pool of PCAP files.

.. envvar:: BROAPT_DUMP_PATH

   :type: ``str`` (path)
   :default: ``FileExtract::prefix`` (Bro script)

   Path to extracted files.

.. envvar:: BROAPT_PCAP_PATH

   :type: ``str`` (path)
   :default: ``/pcap/``

   Path to source PCAP files.

.. envvar:: BROAPT_LOGS_PATH

   :type: ``str`` (path)
   :default: ``/var/log/bro/``

   Path to system logs.

.. envvar:: BROAPT_MIME_MODE

   :type: ``bool``
   :default: ``True``

   If group extracted files by MIME type.

.. envvar:: BROAPT_JSON_MODE

   :type: ``bool``
   :default: ``LogAscii::use_json`` (Bro script)

   Toggle Bro logs in JSON or ASCII format.

.. envvar:: BROAPT_BARE_MODE

   :type: ``bool``
   :default: ``False``

   Run Bro in bare mode (don't load scripts from the ``base/`` directory).

.. envvar:: BROAPT_NO_CHKSUM

   :type: ``bool``
   :default: ``True``

   Ignore checksums of packets in PCAP files when running Bro.

.. envvar:: BROAPT_HASH_MD5

   :type: ``bool``
   :default: ``False``

   Calculate MD5 hash of extracted files.

.. envvar:: BROAPT_HASH_SH1

   :type: ``bool``
   :default: ``False``

   Calculate SH1 hash of extracted files.

.. envvar:: BROAPT_HASH_SHA256

   :type: ``bool``
   :default: ``False``

   Calculate SHA256 hash of extracted files.

.. envvar:: BROAPT_X509_MODE

   :type: ``bool``
   :default: ``False``

   Include X509 information when running Bro.

.. envvar:: BROAPT_ENTROPY_MODE

   :type: ``bool``
   :default: ``False``

   Include file entropy information when running Bro.

.. envvar:: BROAPT_LOAD_MIME

   :type: ``List[str]`` (*case-insensitive*)
   :default: ``None``

   A ``,`` or ``;`` separated string of MIME types to be extracted.

.. envvar:: BROAPT_LOAD_PROTOCOL

   :type: ``List[str]`` (*case-insensitive*)
   :default: ``None``

   A ``,`` or ``;`` separated string of application layer protocols to be extracted,
   can be any of ``dtls``, ``ftp``, ``http``, ``irc`` and ``smtp``.

.. envvar:: BROAPT_FILE_BUFFER

   :type: ``int`` (``uint64``)
   :default: ``Files::reassembly_buffer_size`` (Bro script)

   Reassembly buffer size for file extraction.

.. envvar:: BROAPT_SIZE_LIMIT

   :type: ``int`` (``uint64``)
   :default: ``FileExtract::default_limit`` (Bro script)

   Size limit of extracted files.

.. envvar:: BROAPT_HOOK_CPU

   :type: ``int``
   :default: ``1``

   Number of BroAPT concurrent processes for Python hooks.

BroAPT-App Framework
====================

The BroAPT-App framework only supports configuration through environment variables.

.. envvar:: BROAPT_SCAN_CPU

   :type: ``int``
   :default: ``10``

   Number of BroAPT concurrent processes for extracted file detection.

.. envvar:: BROAPT_MAX_RETRY

   :type: ``int``
   :default: ``3``

   Retry times for failed commands.

.. envvar:: BROAPT_API_ROOT

   :type: ``str`` (path)
   :default: ``/api/``

   Path to the API root folder.

.. envvar:: BROAPT_API_LOGS

   :type: ``str`` (path)
   :default: ``/var/log/bro/api/``

   Path to API detection logs.

.. envvar:: BROAPT_NAME_HOST

   :type: ``str`` (hostname)
   :default: ``localhost``

   Hostname of BroAPT-Daemon server.

.. envvar:: BROAPT_NAME_PORT

   :type: ``int`` (port number)
   :default: ``5000``

   Port number of BroAPT-Daemon server.
