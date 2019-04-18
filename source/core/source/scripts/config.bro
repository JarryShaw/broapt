# All configuration must occur within this file.
# All other files may be overwritten during upgrade
module FileExtraction;

# Configure if store extracted files by MIME types
redef mime = F;

# Configure where extracted files will be stored
redef path = "/dump/";

@if ( path != FileExtract::prefix )
    redef FileExtract::prefix = path;
@endif

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common
# file extraction policies. Example:
@load ./plugins/extract-all-files.bro
