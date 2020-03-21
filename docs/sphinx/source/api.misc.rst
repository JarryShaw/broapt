=========================
Miscellaneous & Auxiliary
=========================

MIME-Extension Mappings
=======================

-----------------
Generate Mappings
-----------------

:File location:
    * Bundled implementation: ``source/utils/mime2ext.py``
    * Cluster implementation: ``cluster/utils/mime2ext.py``

.. note:: This script support all version since Python 2.7.

.. envvar:: BROAPT_FORCE_UPDATE

   :type: ``bool``
   :default: ``False``

   Set the environment variable to ``True`` if you wish to update existing mappings;
   otherwise, it will only add mappings of new MIME types.

The script fetch the MIME types from `IANA registries`_ and try to automatically
match them with the file extensions through |mimetypes|_ database. It will then
dump the mappings to corresponding ``file-extensions.bro`` as discussed in the
:doc:`documentation <api.core.bro.file-extensions>`.

.. _IANA registries: https://www.iana.org/assignments/media-types/media-types.xhtml

.. |mimetypes| replace:: :mod:`mimetypes`
.. _mimetypes: https://docs.python.org/3/library/mimetypes.html

Should there be an unknown MIME type, it will prompt for user to type in the
corresponding file extensions.

--------------------
Fix Missing Mappings
--------------------

:File location:
    * Bundled implementation: ``source/utils/fix-missing.py``
    * Cluster implementation: ``cluster/utils/fix-missing.py``

.. note:: This script support all version since Python 2.7.

.. envvar:: BROAPT_LOGS_PATH

   :type: ``str`` (path)
   :default: ``/var/log/bro/``

   Path to system logs.

In the BroAPT system, when encountering a MIME type not present in the
``file-extensions.bro`` database, it will record such MIME type into
a log file under the log path :data:`const.LOGS_PATH`, named ``processed_mime.log``.

The script will read the log file and try to update the ``file-extensions.bro``
database with these found-missing MIME types.

Bro Script Composers
====================

--------------------
HTTP Method Registry
--------------------

:File location: ``source/utils/http-methods.py``

.. note:: This script support all version since Python 2.7.

As discussed in :doc:`broapt-core`, we have introduced full HTTP methods
registry to the BroAPT system in Bro script ``sites/const/http-methods.bro``.

The script will read the `IANA registries <https://www.iana.org/assignments/http-methods/http-methods.xhtml>`__
and update the builtin ``HTTP::http_methods`` with the fetched data.

--------------------
HTTP Message Headers
--------------------

:File location: ``source/utils/http-header-names.py``

.. note:: This script support all version since Python 2.7.

As discussed in :doc:`broapt-core`, we have introduced full HTTP message
header registry to the BroAPT system in Bro script ``sites/const/http-header-names.bro``.

The script will read the `IANA registries <https://www.iana.org/assignments/message-headers/message-headers.xhtml>`__
and update the builtin ``HTTP::header_names`` with the fetched data.

-------------------------
FTP Commands & Extensions
-------------------------

:File location: ``source/utils/ftp-commands.py``

.. note:: This script support all version since Python 2.7.

As discussed in :doc:`broapt-core`, we have introduced full FTP commands ands
extensions registry to the BroAPT system in Bro script ``sites/const/ftp-commands.bro``.

The script will read the `IANA registries <https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml>`__
and update the builtin ``FTP::logged_commands`` with the fetched data.
