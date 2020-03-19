--------------
Configurations
--------------

:File location:

   * Bundled implementation: ``source/client/scripts/config.bro``
   * Cluster implementation: ``cluster/core/source/scripts/config.bro``

This file contains custom configurations for the Bro IDS at runtime.
It will be automatically regenerated at runtime through the **Bro script composer**,
based on the following environment variables:

* :envvar:`BROAPT_LOGS_PATH`
* :envvar:`BROAPT_PCAP_PATH`
* :envvar:`BROAPT_MIME_MODE`
* :envvar:`BROAPT_HASH_MD5`
* :envvar:`BROAPT_HASH_SHA1`
* :envvar:`BROAPT_HASH_SHA256`
* :envvar:`BROAPT_X509_MODE`
* :envvar:`BROAPT_ENTROPY_MODE`
* :envvar:`BROAPT_DUMP_PATH`
* :envvar:`BROAPT_FILE_BUFFER`
* :envvar:`BROAPT_SIZE_LIMIT`
* :envvar:`BROAPT_JSON_MODE`
* :envvar:`BROAPT_LOAD_MIME`
* :envvar:`BROAPT_LOAD_PROTOCOL`
