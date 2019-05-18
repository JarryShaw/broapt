@load ./extract-http-cookies.bro
# @load ./extract-http-headers.bro
@load ./extract-http-post-body.bro

## https://github.com/hosom/bro-phishing
@load ./bro-phishing

## https://github.com/initconf/smtp-url-analysis
redef old_comm_usage_is_ok=T;
@load ./smtp-url-analysis
