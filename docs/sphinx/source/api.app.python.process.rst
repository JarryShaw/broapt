.. module:: broapt.app.process

--------------------
Detection Processing
--------------------

:File location:

   * Bundled implementation: ``source/client/python/scan.py``
   * Cluster implementation:

      - ``cluster/app/source/python/scan.py``
      - ``cluster/app/source/python/utils/py``

Bundled Implementation
----------------------

.. function:: scan.process(entry: Entry)

   :availability: bundled implementation

   Process extracted files with detection APIs.

   :param Entry entry: File to be processed.

.. function:: scan.make_env(api: API)

   :availability: bundled implementation

   Generate a dictionary of environment variables based on API entry.

   :param API api: API entry from ``api.yml``.
   :rtype: Dict[str, Any]

.. function:: scan.make_cwd(api: API, entry: Optional[Entry] = None, example: bool = False)

   :availability: bundled implementation

   Generate the working directory of API entry.

   :param API api: API entry from ``api.yml``.
   :param Entry entry: File to be processed.
   :param example: If using the fallback detection API ``example``.
   :type example: bool
   :return: Path to the working directory.
   :rtype: str

.. function:: scan.init(api: API, cwd: str, env: Dict[str, Any], mime: str, uuid: str)

   :availability: bundled implementation

   Run the initialisation commands of API entry.

   :param API api: API entry from ``api.yml``.
   :param str cwd: Working directory.
   :param env: Environment variables.
   :type env: Dict[str, Any]
   :param str mime: MIME type.
   :param str uuid: Unique identifier of current scan.
   :return: Exit code (:data:`const.EXIT_SUCCESS` or :data:`const.EXIT_FAILURE`).
   :rtype: int

.. function:: scan.run(command: Union[str, List[str]], cwd: str = None, env: Optional[Dict[str, Any]] = None, mime: str = 'example', file: str = 'unknown')

   :availability: bundled implementation

   Run command with provided settings.

   :param command: Command to execute.
   :type command: Union[str, List[str]]
   :param str cwd: Working dictionary.
   :param env: Environment variables.
   :type env: Dict[str, Any]
   :param str mime: MIME type.
   :param str file: Stem of output log file.
   :return: Exit code (:data:`const.EXIT_SUCCESS` or :data:`const.EXIT_FAILURE`).
   :rtype: int

.. function:: scan.issue(mime: str)

   :availability: bundled implementation

   Called when the execution of API commands failed.

   :param str mime: MIME type.
   :return: Exit code (:data:`const.EXIT_FAILURE`).
   :rtype: int
   :raises APIError: If ``mime`` is ``example``.
   :raises APIWarning: If ``mime`` is **NOT** ``example``.

.. exception:: scan.APIWarning

   :bases: Warning
   :availability: bundled implementation

   Warn if API execution failed.

.. exception:: scan.APIError

   :bases: Exception
   :availability: bundled implementation

   Error if API execution failed.

Cluster Implementation
----------------------

.. function:: process.process(entry: Entry)

   :availability: cluster implementation

   .. seealso:: :func:`scan.process`

.. function:: process.make_env(api: API)

   :availability: cluster implementation

   .. seealso:: :func:`scan.make_env`

.. function:: process.make_cwd(api: API, entry: Optional[Entry] = None, example: bool = False)

   :availability: cluster implementation

   .. seealso:: :func:`scan.make_cwd`

.. function:: process.init(api: API, cwd: str, env: Dict[str, Any], mime: str, uuid: str)

   :availability: cluster implementation

   .. seealso:: :func:`scan.init`

.. function:: process.run(command: Union[str, List[str]], cwd: str = None, env: Optional[Dict[str, Any]] = None, mime: str = 'example', file: str = 'unknown')

   :availability: cluster implementation

   .. seealso:: :func:`scan.run`

.. function:: process.issue(mime: str)

   :availability: cluster implementation

   .. seealso:: :func:`scan.issue`

.. exception:: utils.APIWarning

   :bases: Warning
   :availability: cluster implementation

   .. seealso:: :exc:`scan.APIWarning`

.. exception:: utils.APIError

   :bases: Exception
   :availability: cluster implementation

   .. seealso:: :exc:`scan.APIError`
