----------------------
Command Line Interface
----------------------

:File location:

   * Bundled implementation: ``source/server/python/cli.py``
   * Cluster implementation: ``cluster/daemon/python/cli.py``

For options and configuration details, please refer to
:doc:`configuration <configuration>` documentations.

.. function:: parse_args()

   Parse command line arguments.

   :return: Parsed command line arguments.
   :rtype: argparse.Namespace

.. function:: parse_env()

   Parse provided *dotenv* files for the command line argument
   parser as default values.

   :return: Parsed *dotenv* values.
   :rtype: Dict[str, Any]
