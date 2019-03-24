@load ../writer
@load base/utils/files

module Reass;

export {
    redef enum Log::ID += { LOG_HTTP };

    type log_t: record {
        pkt:        pkt_t   &log;
        is_resp:    bool    &log;
        method:     string  &log &optional;
        target:     string  &log &optional;
        version:    string  &log;
        status:     count   &log &optional;
        phrase:     string  &log &optional;
        host:       string  &log &optional;
        referer:    string  &log &optional;
        filename:   string  &log &optional;
    };

    # Define a logging event. By convention, this is called
    # "log_<stream>".
    global log_http: event(rec: log_t);
}

global HTTP_METHOD: pattern = /GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE/i &redef;
global HTTP_VERSION: pattern = /HTTP\/[0-9]\.[0-9]/i;
global HTTP_STATUS: pattern = /[0-9][0-9][0-9]/i;

hook Reass::predicate(s: string, pkt: pkt_t) {
    local vec: string_vec;

    vec = split_string1(s, /\x0d\x0a\x0d\x0a/);
    if ( |vec| != 2 )
        break;

    local header: string = vec[0];
    local body: string = vec[1];

    vec = split_string1(header, /\x0d\x0a/);
    local startline: string = vec[0];
    local headerfield: string = vec[1];

    vec = split_string_n(startline, /[[:blank:]]+/, F, 2);
    if ( |vec| != 3 )
        break;
    local para1: string = vec[0];
    local para2: string = vec[1];
    local para3: string = vec[2];

    local match1: bool = (para1 == HTTP_METHOD);
    local match2: bool = (para3 == HTTP_VERSION);
    local match3: bool = (para1 == HTTP_VERSION);
    local match4: bool = (para2 == HTTP_STATUS);

    local version: string;
    local rec: log_t;

    local flag_request: bool = F;
    if ( match1 && match2 ) {
        flag_request = T;
        local method: string = para1;
        local target: string = para2;
        version = para3[5:];
        rec = [$pkt=pkt,
               $is_resp=F,
               $method=method,
               $target=target,
               $version=version];
    }

    local flag_response: bool = F;
    if ( match3 && match4 ) {
        flag_response = T;
        version = para1[5:];
        local status: count = to_count(para2);
        local phrase: string = para3;
        rec = [$pkt=pkt,
               $is_resp=T,
               $version=version,
               $status=status,
               $phrase=phrase];
    }

    if ( !flag_request && !flag_response )
        break;

    local fields: string_vec = split_string(headerfield, /\x0d\x0a/);
    local flag_malformed: bool = F;
    for ( i in fields ) {
        vec = split_string1(fields[i], /[[:blank:]]*:[[:blank:]]*/);
        if ( |vec| != 2 ) {
            flag_malformed = T;
            break;
        }

        if ( vec[0] == /Host/i )
            rec$host = vec[1];

        if ( vec[0] == /Referer/i )
            rec$referer = vec[1];

        if ( vec[0] == /Content-Disposition/i )
            rec$filename = extract_filename_from_content_disposition(vec[1]);
    }
    if ( flag_malformed )
        break;

    Log::write(LOG_HTTP, rec);
}

event bro_init() &priority=5 {
    # Specify the "log_http" event here in order for Bro to raise it.
    Log::create_stream(Reass::LOG_HTTP, [$columns=log_t, $ev=Reass::log_http, $path="reass_http"]);
}
