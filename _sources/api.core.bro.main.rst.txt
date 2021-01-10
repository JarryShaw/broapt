-------------------------
``FileExtraction`` Module
-------------------------

:File location:

   * Bundled implementation: ``source/client/scripts/main.bro``
   * Cluster implementation: ``cluster/core/source/scripts/main.bro``

This files is the main implementation of the ``FileExtraction`` module. The main
logic can be simplified as following Bro script:

.. code:: zeek

   module FileExtraction;

   event file_sniff(f: fa_file, meta: fa_metadata) {
       if ( !hook FileExtraction::ignore(f, meta) )
           return;

       if ( !hook FileExtraction::extract(f, meta) ) {
           # scripts to generate an output file name
           local name: string = ...;

           # extract the file to the ``name``
           Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=name]);
       }
   }

where ``FileExtraction::ignore`` and ``FileExtraction::extract`` are the two Bro
``hook`` functions, i.e. predicates, you may customise to affect the extraction
behaviour.
