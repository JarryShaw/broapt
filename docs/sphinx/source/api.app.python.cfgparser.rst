.. module:: broapt.app.cfgparser

-----------------
API Config Parser
-----------------

:File location:

   * Bundled implementation: ``source/client/python/cfgparser.py``
   * Cluster implementation: ``cluster/app/source/python/cfgparser.py``

Dataclasses
-----------

.. class:: cfgparser.API

   A `dataclass`_ for parsed API entry.

   .. attribute:: workdir
      :type: str

      API working directory.

   .. attribute:: environ
      :type: Dict[str, Any]

      API runtime environment variables.

   .. attribute:: install
      :type: List[str]

      List of installation commands.

   .. attribute:: scripts
      :type: List[Union[str, List[str]]]

      List of detection commands.

   .. attribute:: report
      :type: str

      Report generation command.

   .. attribute:: remote
      :type: bool

      If the API required *remote* execution, i.e. through the BroAPT-Daemon server.

   .. attribute:: shared
      :type: str

      Sharing identifier, i.e. which MIME type the API entry is shared with.

   .. attribute:: inited
      :value: multiprocessing.Value('B', False)

      Initied flag.

   .. attribute:: locked
      :type: multiprocessing.Lock

      Multiprocessing runtime lock.

.. _dataclass: https://www.python.org/dev/peps/pep-0557

Functions
---------

.. function:: cfgparser.parse_cmd(context: Dict[str, Any], mimetype: str, environ: Dict[str, Any])

   Parse API of ``mimetype``.

   :param context: API configuration context.
   :param str mimetype: MIME type of the API.
   :param environ: Global environment variables.
   :raises ReportNotFoundError: If ``report`` section not presented in ``context``.

.. function:: cfgparser.parse(root: str)

   Parse API configuration file ``api.yml``.

   :param str root: Root path to the APIs.
   :return: The parsed API entries, i.e. :data:`~cfgparser.API_DICT`.
   :rtype: Dict[str, API]

Constants
---------

.. data:: cfgparser.MEDIA_TYPE
   :type: Tuple[str]

   .. code:: python

         ('application',
          'audio',
          # 'example',  ## preserved for default API
          'font',
          'image',
          'message',
          'model',
          'multipart',
          'text',
          'video')

   Possible media types.

.. data:: cfgparser.API_DICT
   :type: Dict[str, API]

   Database for API entries.

.. data:: cfgparser.API_LOCK
   :type: Dict[str, multiprocessing.Lock]

   Database for multiprocessing lock.

.. data:: cfgparser.API_INIT
   :type: Dict[str, multiprocessing.Value]

   Database for inited flags.

Exceptions
----------

.. exception:: cfgparser.ConfigError

   :bases: :exc:`Exception`

   Invalid config.

.. exception:: cfgparser.DefaultNotFoundError

   :bases: :exc:`~cfgparser.ConfigError`

   The default fallback API for MIME type ``example`` not found.

.. exception:: cfgparser.ReportNotFoundError

   :bases: :exc:`~cfgparser.ConfigError`

   The ``report`` section not found in API.
