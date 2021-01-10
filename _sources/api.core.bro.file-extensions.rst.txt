-----------------------
MIME-Extension Mappings
-----------------------

:File location:

   * Bundled implementation: ``source/client/scripts/file-extensions.bro``
   * Cluster implementation: ``cluster/core/source/scripts/file-extensions.bro``

This file contains a Bro ``table`` mapping MIME types to possible file extensions.
The MIME types are fetched from `IANA registries`_ and the file extensions are
provided *semi-automatically* through |mimetypes|_ database.

.. _IANA registries: https://www.iana.org/assignments/media-types/media-types.xhtml

.. |mimetypes| replace:: :mod:`mimetypes`
.. _mimetypes: https://docs.python.org/3/library/mimetypes.html

This Bro script can be generated from the the ``mime2ext.py`` script as we
described in the :doc:`api.misc` section.
