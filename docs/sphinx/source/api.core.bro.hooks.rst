-------------------
Extract by Protocol
-------------------

:File location:

   * Bundled implementation: ``source/client/scripts/hooks/``
   * Cluster implementation: ``cluster/core/source/scripts/hooks/``

This fold contains Bro ``hook`` functions to toggle if extract files transferred
through a certain application layer protocol. Such scripts will be loaded based
on :envvar:`BROAPT_LOAD_PROTOCOL` environment variable.

Supported protocols are:

* DTLS
* FTP
* HTTP
* IRC
* SMTP

To extract all files transferred through HTTP, i.e. ``extract-http.bro`` in
the folder, the Bro ``hook`` function should be as below:

.. code:: zeek

   @load ../__load__.bro
   @load base/protocols/http/entities.bro

   module FileExtraction;

   hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=15 {
      if ( f$source == "HTTP" )
         break;
   }

.. note::

   We load ``base/protocols/http/entities.bro`` to support the script even
   running in *bare* mode.
