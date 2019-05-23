# redefined constants
@load ./const

# add new fields to http.log
@load ./extract-http-cookies.bro
@load ./extract-http-post-body.bro
@load ./extract-http-headers

# calculate hash value of all files
@load ./hash-all-files.bro

## https://github.com/hosom/bro-phishing
@load ./bro-phishing

## https://github.com/initconf/smtp-url-analysis
redef old_comm_usage_is_ok=T;
@load ./smtp-url-analysis
