# All configuration must occur within this file.
# All other files may be overwritten during upgrade
module Reassm;

# Configure where reassembled files will be stored
redef path = "contents";

# Configure what prefix will be used for reassembled files
redef reassembly_prefix = "";

# Configure if reassemble TCP content from originator-side
redef contents_orig = T;

# Configure if reassemble TCP content from responder-side
redef contents_resp = T;

# Configure if change log files to JSON format.
redef use_json = F;
