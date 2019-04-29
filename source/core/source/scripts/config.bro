# All configuration must occur within this file.
# All other files may be overwritten during upgrade
module FileExtraction;

# Configure if store extracted files by MIME types
redef mime = T;

# Configure buffer size for file reassembly
redef size = 0xffffffffffffffff;

# Configure where extracted files will be stored
redef path = "/dump/";

## Configure path to missing MIME log file
redef logs = "/var/log/bro/processed_mime.log";

@if ( path != FileExtract::prefix )
    redef FileExtract::prefix = path;
@endif

@if ( size != Files::reassembly_buffer_size )
    redef Files::reassembly_buffer_size = size;
@endif

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common
# file extraction policies. Example:
@load ./plugins/extract-all-files.bro
