@load base/utils/files
# @load misc/dump-events

module Reass;

export {
    ## Path to store files
    const path: string = "contents" &redef;
    ## Prefix of reassembled files
    const reassembly_prefix: string = "" &redef;

    ## Reassemble TCP content from originator-side
    const contents_orig: bool = T &redef;
    ## Reassemble TCP content from responder-side
    const contents_resp: bool = T &redef;

    redef enum Log::ID += { LOG_CONN };

    type Info: record {
        ts:     time    &log;
        id:     conn_id &log;
        uid:    string  &log;
        cnt:    count   &log &default=0;
    };

    # Define a logging event. By convention, this is called
    # "log_<stream>".
    global log_conn: event(rec: Info);

    ## Write logs in JSON format
    const use_json: bool = F &redef;
}

@if ( contents_orig )
    redef tcp_content_deliver_all_orig=T;
@endif

@if ( contents_resp )
    redef tcp_content_deliver_all_resp=T;
@endif

@if ( use_json )
    redef LogAscii::use_json = T;
@endif

global default_table: table[conn_id] of count;

function get_count(key: conn_id): count {
    if ( key in default_table )
        default_table[key] += 1;
    else
        default_table[key] = 0;
    return default_table[key];
}

event new_connection_contents(c: connection) &priority=5 {
    local cnt: count = get_count(c$id);
    local rec: Info = [$ts=network_time(), $id=c$id, $uid=c$uid, $cnt=cnt];

    print c$id;
    Log::write(Reass::LOG_CONN, rec);

    local orig_file = generate_extraction_filename(reassembly_prefix, c, fmt("orig_%s.dat", cnt));
    local orig_f = open(fmt("%s/%s", path, orig_file));
    set_contents_file(c$id, CONTENTS_ORIG, orig_f);

    local resp_file = generate_extraction_filename(reassembly_prefix, c, fmt("resp_%s.dat", cnt));
    local resp_f = open(fmt("%s/%s", path, resp_file));
    set_contents_file(c$id, CONTENTS_RESP, resp_f);
}

event bro_init() &priority=5 {
    # Specify the "log_conn" event here in order for Bro to raise it.
    Log::create_stream(Reass::LOG_CONN, [$columns=Info, $ev=Reass::log_conn, $path="reass_conn"]);
}
