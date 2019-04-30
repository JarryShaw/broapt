# All configuration must occur within this file.
# All other files may be overwritten during upgrade
module FileExtraction;

# Configure if store extracted files by MIME types
redef mime = T;

## Configure path to missing MIME log file
redef logs = "/var/log/bro/processed_mime.log";

# Configure where extracted files will be stored
redef path = "/dump/";

@if ( path != FileExtract::prefix )
    redef FileExtract::prefix = path;
@endif

# Configure buffer size for file reassembly
redef buffer_size = 0xffffffffffffffff;

@if ( buffer_size != Files::reassembly_buffer_size )
    redef Files::reassembly_buffer_size = buffer_size;
@endif

# Configure size limit for extracted files
redef size_limit = 0;

@if ( size_limit != FileExtract::default_limit )
    redef FileExtract::default_limit = size_limit;
@endif

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common
# file extraction policies. Example:
@load ./plugins/extract-all-files.bro
