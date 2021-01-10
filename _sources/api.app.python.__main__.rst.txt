-----------------
System Entrypoint
-----------------

:File location:

   * Bundled implementation:

     - ``source/client/python/remote.py``
     - ``source/client/python/scan.py``

   * Cluster implementation: ``cluster/app/source/python/__main__.py``

In **bundled implementation**, the :doc:`api.core.python.remote` module (:mod:`remote`) starts a
background process for the BroAPT-App framework; whilst the :doc:`api.app.python.process` module
(:mod:`process`) contains :doc:`main processing logic <api.app.python.process>` as well as the
original system entrypoint.

In **cluster implementation**, this file wraps the whole system and make the
``python`` folder callable as a module where the ``__main__.py`` will be
considered as the entrypoint.

Constants
---------

.. data:: __main__.FILE_REGEX
   :type: re.Pattern

   :availability: cluster implementation

   .. code:: python

      re.compile(r'''
          # protocol prefix
          (?P<protocol>DTLS|FTP_DATA|HTTP|IRC_DATA|SMTP|\S+)
          -
          # file UID
          (?P<fuid>F\w+)
          \.
          # PCAP source
          (?P<pcap>.+?)
          \.
          # media-type
          (?P<media_type>application|audio|example|font|image|message|model|multipart|text|video|\S+)
          \.
          # subtype
          (?P<subtype>\S+)
          \.
          # file extension
          (?P<extension>\S+)
      ''', re.IGNORECASE | re.VERBOSE)

   Regular expression to match and fetch information from extracted files.

   .. seealso:: :data:`const.FILE_REGEX`

Dataclasses
-----------

.. class:: scan.MIME

   :availability: bundled implementation

   A `dataclass`_ for parsed MIME type.

   .. attribute:: media_type
      :type: str

      Media type.

   .. attribute:: subtype
      :type: str

      Subtype.

   .. attribute:: name
      :type: str

      MIME type.

.. class:: __main__.MIME

   :availability: cluster implementation

   .. seealso:: :class:`scan.MIME`

.. class:: scan.Entry

   :availability: bundled implementation

   A `dataclass`_ for extracted file entry.

   .. attribute:: path
      :type: str

      File path.

   .. attribute:: uuid
      :type: str

      UUID parsed from file.

   .. attribute:: mime
      :type: MIME

      Parsed MIME type :class:`dataclass <scan.MIME>`.

   .. note::

      This `dataclass`_ supports ordering with power of |total_ordering|_.

      .. |total_ordering| replace:: :func:`functools.total_ordering`
      .. _total_ordering: https://docs.python.org/3/library/functools.html#functools.total_ordering

.. class:: __main__.Entry

   :availability: cluster implementation

   .. seealso:: :class:`scan.Entry`

.. _dataclass: https://www.python.org/dev/peps/pep-0557

Bundled Implementation
----------------------

:mod:`scan` Module
~~~~~~~~~~~~~~~~~~

.. function:: scan.scan(local_name: str)

   :availability: bundled implementation

   Parse then start processing of the given file.

   .. seealso:: :func:`scan.process`

.. function:: scan.lookup(path: str)

   :availability: bundled implementation

   Fetch all extracted files to be processed from the given path.

   :param str path: Path to extracted files.
   :return: List of extracted files.
   :rtype: List[str]

:mod:`remote` Module
~~~~~~~~~~~~~~~~~~~~

Framework Mainloop
++++++++++++++++++

.. function:: remote.remote_dump()

   :availability: bundled implementation

   Runtime mainloop for BroAPT-App framework.

   The function will start as an *indefinite* loop to fetch path to extracted
   files from :data:`const.QUEUE_DUMP`, and perform :func:`~scan.scan`
   on them.

   When :data:`~remote.JOIN_DUMP` is set to ``True``, the function will
   break from the loop.

Signal Handling
+++++++++++++++

.. function:: remote.join_dump(*args, **kwargs)

   :availability: bundled implementation

   Toggle :data:`~remote.JOIN_DUMP` to ``True``.

   .. note:: This function is registered as handler for ``SIGUSR1```.

.. data:: remote.JOIN_DUMP
   :value: multiprocessing.Value('B', False)

   :availability: bundled implementation

   Flag to stop the :func:`~remote.remote_dump` background process.

Cluster Implementation
----------------------

.. function:: __main__.listdir(path: str)

   :availability: cluster implementation

   Fetch and parse all extracted files in the given path.

   :param str path: Path to extracted files.
   :return: List of parsed :class:`entry <scan.Entry>` for extracted files.
   :rtype: List[Entry]

.. function:: __main__.check_history()

   :availability: cluster implementation

   Check processed extracted files.

   .. note::

      Processed extracted files will be recorded at :data:`const.DUMP`.

   :return: List of processed extracted files.
   :rtype: List[str]

.. function:: __main__.main()

   :availability: cluster implementation

   Run the BroAPT-Core framework.

   :return: Exit code.
   :rtype: int

   .. seealso:: :func:`__main__.process`
