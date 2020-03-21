.. module:: broapt.core.logparser

--------------
Bro Log Parser
--------------

:File location:

   * Bundled implementation: ``source/client/python/logparser.py``
   * Cluster implementation: ``cluster/core/source/python/logparser.py``

.. important::

   This module has been deprecated for production reasons.
   Please use the `ZLogging`_ module for parsing Bro logs.

   .. _ZLogging: https://zlogging.jarryshaw.me

Dataclasses
-----------

.. class:: logparser.TEXTInfo

   A `dataclass`_ for parsed ASCII log file.

   .. attribute:: format
      :value: 'text'

      Log file format.

   .. attribute:: path
      :type: str

      Path to log file.

   .. attribute:: open
      :type: datetime.datetime

      Open time of log file.

   .. attribute:: close
      :type: datetime.datetime

      Close time of log file.

   .. attribute:: context
      :type: pandas.DataFrame

      Parsed log context.

   .. attribute:: exit_with_error
      :type: bool

      If log file exited with error, i.e. close time :attr:`~logparser.TEXTInfo.close`
      doesn't present in the log file.

.. class:: logparser.JSONInfo

   A `dataclass`_ for parsed JSON log file.

   .. attribute:: format
      :value: 'json'

      Log file format.

   .. attribute:: context
      :type: pandas.DataFrame

      Parsed log context.

.. _dataclass: https://www.python.org/dev/peps/pep-0557

Field Parsers
-------------

.. data:: logparser.set_separator
   :type: str

   Separator of ``set`` & ``vector`` values in ASCII logs.

.. data:: logparser.empty_field
   :type: str

   Separator of *empty* fields in ASCII logs.

.. data:: logparser.unset_field
   :type: str

   Separator of *unset* fields in ASCII logs.

   .. note::

      If the field is ``unset_field``, then the parsers below will
      return ``None``.

.. function:: logparser.set_parser(s: str, t: Type[T])

   Parse ``set`` field.

   :param str s: Field string.
   :param type t: Type of ``set`` elements.
   :rtype: ``Set[T]``

.. function:: logparser.vector_parser(s: str, t: Type[T])

   Parse ``vector`` field.

   :param str s: Field string.
   :param type t: Type of ``vector`` elements.
   :rtype: ``List[T]``

.. function:: logparser.str_parser(s: str)

   Parse ``string`` field.

   :param str s: Field string.
   :rtype: ``str``

   .. note::

      To *unescape* the escaped bytes characters, we use the ``unicode_escape``
      encoding to decode the parsed string.

.. function:: logparser.port_parser(s: str)

   Parse ``port`` field.

   :param str s: Field string.
   :rtype: ``int`` (``uint16``)

.. function:: logparser.int_parser(s: str)

   Parse ``int`` field.

   :param str s: Field string.
   :rtype: ``int`` (``int64``)

.. function:: logparser.count_parser(s: str)

   Parse ``count`` field.

   :param str s: Field string.
   :rtype: ``int`` (``uint64``)

.. function:: logparser.addr_parser(s: str)

   Parse ``addr`` field.

   :param str s: Field string.
   :rtype: ``Union[ipaddress.IPv4Address, ipaddress.IPv6Address]``

.. function:: logparser.subnet_parser(s: str)

   Parse ``subnet`` field.

   :param str s: Field string.
   :rtype: ``Union[ipaddress.IPv4Network, ipaddress.IPv6Network]``

.. function:: logparser.time_parser(s: str)

   Parse ``time`` field.

   :param str s: Field string.
   :rtype: ``datetime.datetime``

.. function:: logparser.float_parser(s: str)

   Parse ``float`` field.

   :param str s: Field string.
   :rtype: ``decimal.Decimal`` (*precision* set to ``6``)

.. function:: logparser.interval_parser(s: str)

   Parse ``interval`` field.

   :param str s: Field string.
   :rtype: ``datetime.timedelta``

.. function:: logparser.enum_parser(s: str)

   Parse ``enum`` field.

   :param str s: Field string.
   :rtype: ``enum.Enum``

.. function:: logparser.bool_parser(s: str)

   Parse ``bool`` field.

   :param str s: Field string.
   :rtype: ``bool``
   :raises ValueError: If ``s`` is not a valid value, i.e. any of
      :data:`~logparser.unset_field`, ``'T'`` (``True``) or ``'F'``
      (``False``).

.. data:: logparser.type_parser
   :value: collections.defaultdict(lambda: str_parser, dict(
               string=str_parser,
               port=port_parser,
               enum=enum_parser,
               interval=interval_parser,
               addr=addr_parser,
               subnet=subnet_parser,
               int=int_parser,
               count=count_parser,
               time=time_parser,
               double=float_parser,
               bool=bool_parser,
           ))

   Mapping for Bro types and corresponding parser function.

Log Parsers
-----------

.. function:: logparser.parse_text(file: io.TextIOWrapper, line: str, hook: Optional[Dict[str, Callable[[str], Any]])

   Parse ASCII logs.

   :param file: Log file opened in read (``'r'``) mode.
   :param str line: First line of the log file (used for format detection by :func:`~logparser.parse`).
   :param hook: Addition parser mappings to register in :data:`~logparser.type_parser`.
   :rtype: TEXTInfo

.. function:: logparser.parse_text(file: io.TextIOWrapper, line: str)

   Parse JSON logs.

   :param file: Log file opened in read (``'r'``) mode.
   :param str line: First line of the log file (used for format detection by :func:`~logparser.parse`).
   :rtype: JSONInfo

.. function:: logparser.parse(filename: str, hook: Optional[Dict[str, Callable[[str], Any]])

   Parse Bro logs.

   :param str filename: Log file to be parsed.
   :param hook: Addition parser mappings to register in :data:`~logparser.type_parser` when processing
      ASCII logs for :func:`~logparser.parse_text`.
   :rtype: Union[TEXTInfo, JSONInfo]

   .. note::

      The function will automatically detect if the given log file is in
      ASCII or JSON format.

Module Entry
------------

.. function:: logparser.main()

   .. code:: shell

      python logparser.py [filename ...]

   Wrapper function to parse and *pretty* print log files.
