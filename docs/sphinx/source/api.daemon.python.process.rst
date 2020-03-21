-----------------
Detection Process
-----------------

:File location:

   * Bundled implementation: ``source/server/python/process.py``
   * Cluster implementation: ``cluster/daemon/python/process.py``

.. function:: process.process(info: INFO)

   Process extracted files with detection information.

   :param INFO info: File to be processed.
   :return: If detection process exit on success.
   :rtype: bool

.. function:: process.make_env(info: INFO)

   Generate a dictionary of environment variables based on request information.

   :param INFO info: Detection request information.
   :rtype: Dict[str, Any]

.. function:: process.make_cwd(info: INFO)

   Generate the working directory of detection information.

   :param INFO info: Detection request information.
   :return: Path to the working directory.
   :rtype: str

.. function:: process.init(info: INFO)

   Run the initialisation commands of detection information.

   :param INFO info: Detection request information.
   :return: Exit code (:data:`const.EXIT_SUCCESS` or :data:`const.EXIT_FAILURE`).
   :rtype: int

.. function:: process.run(command: Union[str, List[str]], info: INFO, file: str = 'unknown')

   Run command with provided settings.

   :param command: Command to execute.
   :type command: Union[str, List[str]]
   :param INFO info: Detection request information.
   :param str file: Stem of output log file.
   :return: Exit code (:data:`const.EXIT_SUCCESS` or :data:`const.EXIT_FAILURE`).
   :rtype: int
