----------------
Common Constants
----------------

:File location:

   * Bundled implementation: ``source/server/python/const.py``
   * Cluster implementation: ``cluster/daemon/python/const.py``

.. data:: const.KILL_SIGNAL

   :type: ``int``
   :environ: :envvar:`BROAPT_KILL_SIGNAL`

   Daemon kill signal.

.. data:: const.SERVER_NAME_HOST

   :type: ``str``
   :environ: :envvar:`BROAPT_SERVER_HOSTs`

   The hostname to listen on.

.. data:: const.SERVER_NAME_PORT

   :type: ``int``
   :environ: :envvar:`BROAPT_SERVER_PORT`

.. data:: const.DOCKER_COMPOSE

   :type: ``str``
   :environ: :envvar:`BROAPT_DOCKER_COMPOSE`

   Path to BroAPT's compose file.

.. data:: const.DUMP_PATH

   :type: ``str``
   :environ: :envvar:`BROAPT_DUMP_PATH`

   Path to extracted files.

.. data:: const.LOGS_PATH

   :type: ``str``
   :environ: :envvar:`BROAPT_LOGS_PATH`

   Path to log files.

.. data:: const.API_LOGS

   :type: ``str``
   :environ: :envvar:`BROAPT_API_LOGS`

   Path to API runtime logs.

.. data:: const.API_ROOT

   :type: ``str``
   :environ: :envvar:`BROAPT_API_ROOT`

   Path to detection APIs.

.. data:: const.INTERVAL

   :type: ``float``
   :environ: :envvar:`BROAPT_INTERVAL`

   Sleep interval.

.. data:: const.MAX_RETRY

   :type: ``str``
   :environ: :envvar:`BROAPT_MAX_RETRY`

   Command retry.

.. data:: const.EXIT_SUCCESS
   :value: 0

   :type: ``int``

   Exit code upon success.

.. data:: const.EXIT_FAILURE
   :value: 1

   :type: ``int``

   Exit code upon failure.

.. data:: const.FILE

   :type: ``str``

   .. code:: python

      os.path.join(LOGS_PATH, 'dump.log')

   Path to file system database of processed extracted files.

.. data:: const.FAIL

   :type: ``str``

   .. code:: python

      os.path.join(LOGS_PATH, 'fail.log')

   Path to file system database of failed processing extracted files.
