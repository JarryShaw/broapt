# All configuration must occur within this file.
# All other files may be overwritten during upgrade
module FileExtraction;

# Configure if store extracted files by MIME types
redef mime = T;

# Configure where extracted files will be stored
redef path = "/Users/jarryshaw/Documents/GitHub/broapt/source/dump/";

## Configure path to missing MIME log file
redef logs = "/Users/jarryshaw/Documents/GitHub/broapt/source/logs/processed_mime.log";

@if ( path != FileExtract::prefix )
    redef FileExtract::prefix = path;
@endif

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common
# file extraction policies. Example:
@load ./plugins/extract-white-list.bro
