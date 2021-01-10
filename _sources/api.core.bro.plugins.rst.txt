--------------------
Extract by MIME Type
--------------------

:File location:

   * Bundled implementation: ``source/client/scripts/plugins/``
   * Cluster implementation: ``cluster/core/source/scripts/plugins/``

This fold contains Bro ``hook`` functions to toggle if extract files of a certain
MIME type. Such files will be generated based on :envvar:`BROAPT_LOAD_MIME` environment
variable.

To extract all files, i.e. ``extract-all-files.bro`` in the folder, the Bro
``hook`` function should be as below:

.. code:: zeek

   @load ../__load__.bro

   module FileExtraction;

   hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=10 {
      break;
   }
