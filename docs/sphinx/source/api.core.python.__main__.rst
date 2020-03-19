-----------------
System Entrypoint
-----------------

:File location:

   * Bundled implementation: ``source/client/python/__main__.py``
   * Cluster implementation:

     * BroAPT-Core framework: ``cluster/core/source/python/__main__.py``
     * BroAPT-App framework: ``cluster/app/source/python/__main__.py``

This file wraps the whole system and make the ``python`` folder callable
as a module where the ``__main__.py`` will be considered as the entrypoint.

.. data:: __main__.PCAP_MGC
   :value: (b'\xa1\xb2\x3c\x4d',
            b'\xa1\xb2\xc3\xd4',
            b'\x4d\x3c\xb2\xa1',
            b'\xd4\xc3\xb2\xa1',
            b'\x0a\x0d\x0d\x0a')

   :availability: Bundled & Cluster Implementation

   A tuple of magic numbers for PCAP files::

      a1 b2 3c 4d  # PCAP files in big endian with nanosecond timestamp
      a1 b2 c3 d4  # PCAP files in big endian
      4d 3c b2 a1  # PCAP files in little endian with nanosecond timestamp
      d4 c3 b2 a1  # PCAP files in little endian
      0a 0d 0d 0a  # PCAPng files

.. function:: __main__.is_pcap(file)

   :availability: Bundled & Cluster Implementation

   Check if ``file`` is a valid PCAP file with help of |libmagic|_.

   :param str file: Path of the file to be checked.
   :return: If is a valid PCAP file.
   :rtype: bool

.. |libmagic| replace:: ``libmagic``
.. _libmagic: https://pypi.org/project/python-libmagic

.. function:: __main__.listdir(path)

   :availability: Bundled & Cluster Implementation

   Fetch all files under ``path``.

   :param str path: Path to be fetched.
   :return: All files under ``path``.
   :rtype: List[str]

.. function:: __main__.parse_args(argv)

   :availability: Bundled & Cluster Implementation

   Parse command line arguments (path to PCAP files) and fetch valid
   PCAP files.

   .. note::

      If a directory is provided, it will be recursively listed with
      :func:`~__main__.listdir`.

   :param argv: Command line arguments.
   :type argv: List[str]
   :return: List of valid PCAP files.
   :rtype: List[str]

.. function:: __main__.check_history()

   :availability: Bundled & Cluster Implementation

   Check processed PCAP files.

   .. note::

      Processed PCAP files will be recorded at :data:`const.FILE`.

   :return: List of processed PCAP files.
   :rtype: List[str]

.. function:: __main__.main_with_args()

   :availability: Bundled & Cluster Implementation

   Run the BroAPT system **with** command line arguments.

   .. note::

      The process will exit once all PCAP files fetched from the paths
      given by the command line arguments are processed.

   :return: Exit code.
   :rtype: int

.. function:: __main__.main_with_no_args()

   :availability: Bundled & Cluster Implementation

   Run the BroAPT system **without** command line arguments.

   .. note::

      The process will run and check for new PCAP files from :data:`const.PCAP_PATH`
      indefinitely.


.. function:: __main__.main()

   :availability: Bundled & Cluster Implementation

   Run the BroAPT system under the context of :func:`remote.remote_proc`.

   .. seealso::

      * :func:`~__main__.main_with_args`
      * :func:`~__main__.main_with_no_args`
