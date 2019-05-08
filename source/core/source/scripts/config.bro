# All configuration must occur within this file.
# All other files may be overwritten during upgrade
module FileExtraction;

# Configure if store extracted files by MIME types
redef mime = T;

# Configure path to missing MIME log file
redef logs = "/var/log/bro/processed_mime.log";

# Configure if include hash information
redef hash = F;

@if ( hash )
    @load base/files/hash
@endif

# Configure if include X509 information
redef x509 = F;

@if ( x509 )
    @load base/files/x509
@endif

# Configure if include entropy information
redef entropy = F;

@if ( entropy )
    @load policy/frameworks/files/entropy-test-all-files.bro
@endif

# Configure log in ASCII or JSON format
redef use_json = LogAscii::use_json;

@if ( use_json != LogAscii::use_json )
    redef LogAscii::use_json = use_json;
@endif

# Configure hash salt
redef file_salt = Files::salt;

@if ( file_salt != Files::salt )
    redef Files::salt = file_salt;
@endif

# Configure buffer size for file reassembly
redef file_buffer = Files::reassembly_buffer_size;

@if ( file_buffer != Files::reassembly_buffer_size )
    redef Files::reassembly_buffer_size = file_buffer;
@endif

# Configure where extracted files will be stored
redef path_prefix = FileExtract::prefix;

@if ( path_prefix != FileExtract::prefix )
    redef FileExtract::prefix = path_prefix;
@endif

# Configure size limit for extracted files
redef size_limit = FileExtract::default_limit;

@if ( size_limit != FileExtract::default_limit )
    redef FileExtract::default_limit = size_limit;
@endif

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common
# file extraction policies. Example:
@load ./plugins/extract-all-files.bro
