--------------------
`Flask`_ Application
--------------------

:File location:

   * Bundled implementation: ``source/server/python/daemon.py``
   * Cluster implementation: ``cluster/daemon/python/daemon.py``

URL Routing
-----------

.. function:: daemon.root()

   :route: ``/api``
   :methods: ``GET``

   Display help message :data:`~daemon.__help__`.

.. function:: daemon.help_()

   :route: ``/api/v1.0``
   :methods: ``GET``

   Display help message :data:`~daemon.HELP_v1_0`.

.. function:: daemon.list_()

   :route: ``/api/v1.0/list``
   :methods: ``GET``

   List of detection process information.

   0. Information of running processes from :data:`~daemon.RUNNING`:

   .. code:: json

      {
        "id": "...",
        "initied": null,
        "scanned": true,
        "reported: null,
        "deleted": false
      }

   1. Information of finished processes from :data:`~daemon.SCANNED`:

      * If the process exited on success:

        .. code:: json

           {
             "id": "...",
             "initied": null,
             "scanned": true,
             "reported: true,
             "deleted": false
           }

      * If the process exited on failure:

        .. code:: json

           {
             "id": "...",
             "initied": null,
             "scanned": true,
             "reported: false,
             "deleted": false
           }

.. function:: get_none()

   :route: ``/api/v1.0/report``
   :methods: ``GET``

   Display help message:

   .. code:: text

      ID Required: /api/v1.0/report/<id>

.. function:: get(id_: str)

   :route: ``/api/v1.0/report/<id>``
   :methods: ``GET``

   Fetch detection status of ``id_``.

   0. If ``id_`` in :data:`~daemon.RUNNING`:

      .. code:: json

         {
           "id": "...",
           "initied": null,
           "scanned": false,
           "reported: null,
           "deleted": false
         }

   1. If ``id_`` in :data:`~daemon.SCANNED`:

      * If the process exited on success:

        .. code:: json

           {
             "id": "...",
             "initied": null,
             "scanned": true,
             "reported: true,
             "deleted": false
           }

      * If the process exited on failure:

        .. code:: json

           {
             "id": "...",
             "initied": null,
             "scanned": true,
             "reported: false,
             "deleted": false
           }

   2. If ``id_`` not found, raises ``404 Not Found`` with :func:`~daemon.id_not_found`.

.. function:: daemon.scan()

   :route: ``/api/v1.0/scan``
   :methods: ``POST``

   Perform *remote* detection on target file.

   The ``POST`` data should be a JSON object with following fields:

   :param string name: path to the extracted file
   :param string mime: MIME type
   :param string uuid: unique identifier
   :param report: report generation commands
   :type report: string | string[]
   :param string shared: shared detection API identifier
   :param boolean inited: API initialised
   :param string workdir: working directory
   :param environ: environment variables
   :type environ: object
   :param install: initialisation commands
   :type install: string | string[]
   :param scripts: detection commands
   :type scripts: string | string[]

   If **NO** JSON data provided, raises ``400 Bad Request`` with :func:`~daemon.invalid_info`.

   After performing detection :func:`process.process` on the target file,
   returns a JSON object containing detection report:

   0. If detection exits on success:

      .. code:: json

         {
           "id": "...",
           "initied": true,
           "scanned": true,
           "reported: true,
           "deleted": false
         }

   1. If detection exists on failure:

      * If detection fails when initialising:

         .. code:: json

            {
              "id": "...",
              "initied": false,
              "scanned": true,
              "reported: false,
              "deleted": false
            }

      * If detection fails when processing:

         .. code:: json

            {
              "id": "...",
              "initied": true,
              "scanned": true,
              "reported: false,
              "deleted": false
            }

.. function:: delete_none()

   :route: ``/api/v1.0/delete``
   :methods: ``DELETE``

   Display help message:

   .. code:: text

      ID Required: /api/v1.0/delete/<id>

.. function:: delete(id_: str)

   :route: ``/api/v1.0/delete/<id>``
   :methods: ``DELETE``

   Delete detection status of ``id_``.

   0. If ``id_`` in :data:`~daemon.RUNNING`:

      .. code:: json

         {
           "id": "...",
           "initied": null,
           "scanned": false,
           "reported: null,
           "deleted": true
         }

   1. If ``id_`` in :data:`~daemon.SCANNED`:

      * If the process exited on success:

        .. code:: json

           {
             "id": "...",
             "initied": null,
             "scanned": true,
             "reported: true,
             "deleted": true
           }

      * If the process exited on failure:

        .. code:: json

           {
             "id": "...",
             "initied": null,
             "scanned": true,
             "reported: false,
             "deleted": true
           }

   2. If ``id_`` not found:

      .. code:: json

         {
           "id": "...",
           "initied": null,
           "scanned": null,
           "reported: null,
           "deleted": true
         }

Error Handlers
--------------

.. function:: daemon.invalid_id(error: Exception)

   Handler of ``ValueError``.

   .. code:: json

      {
        "status": 400,
        "error": "...",
        "message": "invalid ID format"
      }

.. function:: daemon.invalid_info(error: Exception)

   Handler of ``400 Bad Request`` and ``KeyError``.

   .. code:: json

      {
        "status": 400,
        "error": "...",
        "message": "invalid info format"
      }

.. function:: daemon.id_not_found(error: Exception)

   Handler of ``404 Not Found``.

   .. code:: json

      {
        "status": 404,
        "error": "...",
        "message": "ID not found"
      }

Dataclasses
-----------

.. class:: daemon.INFO

   A `dataclass`_ for requested detection API information.

   .. attribute:: name
      :type: str

      Path to the extracted file.

   .. attribute:: uuid
      :type: str

      Unique identifier of current process.

   .. attribute:: mime
      :type: str

      MIME type.

   .. attribute:: report
      :type: str

      Report generation command.

   .. attribute:: inited
      :type: manager.Value

      Initied flag.

   .. attribute:: locked
      :type: multiprocessing.Lock

      Multiprocessing runtime lock.

   .. attribute:: workdir
      :type: str

      API working directory.

   .. attribute:: environ
      :type: Dict[str, Any]

      API runtime environment variables.

   .. attribute:: install
      :type: List[Union[str, List[str]]]

      List of installation commands.

   .. attribute:: scripts
      :type: List[Union[str, List[str]]]

      List of detection commands.

.. _dataclass: https://www.python.org/dev/peps/pep-0557

Constants
---------

.. data:: daemon.app
   :value: flask.Flask(__name__)

   `Flask`_ application.

.. _Flask: https://flask.palletsprojects.coms

.. data:: daemon.HELP_v1_0
   :type: str

   .. code:: text

      BroAPT Daemon APIv1.0 Usage:

      - GET    /api/v1.0/list
      - GET    /api/v1.0/report/<id>
      - POST   /api/v1.0/scan data={"key": "value"}
      - DELETE /api/v1.0/delete/<id>

.. data:: daemon.__help__
   :type: str

   .. code:: text

      BroAPT Daemon API Usage:

      # v1.0

      - GET    /api/v1.0/list
      - GET    /api/v1.0/report/<id>
      - POST   /api/v1.0/scan data={"key": "value"}
      - DELETE /api/v1.0/delete/<id>

.. data:: daemon.manager
   :value: multiprocessing.Manager()

   Multiprocessing manager instanace.

.. data:: daemon.RUNNING
   :value: manager.list()

   :type: ``List[uuid.UUID]``

   List of running detection processes.

.. data:: daemon.SCANNED
   :value: manager.dict()

   :type: ``Dict[uuid.UUID, bool]``

   Record of finished detection processes and exit on success.

.. data:: daemon.APILOCK
   :value: manager.dict()

   :type: ``Dict[str, multiprocessing.Lock]``

   Record of API multiprocessing locks.

.. data:: daemon.APIINIT
   :value: manager.dict()

   :type: ``Dict[str, multiprocessing.Value]``

   Record of API initialised flags.
