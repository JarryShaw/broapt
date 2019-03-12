@load base/utils/files
# @load misc/dump-events

module Reass;

export {
    ## Path to store logs
    const log_prefix: string = "logs" &redef;

    ## Record TCP content from originator-side
    const contents_orig: bool = T &redef;
    ## Record TCP content from responder-side
    const contents_resp: bool = T &redef;

    ## packet dict
    type Info: record {
        conn:       connection;
        is_orig:    bool;
        id:         conn_id     &log;
        bufid:      string      &log;   # original packet identifier
        ack:        string      &log;   # acknowledgement
        dsn:        string      &log;   # data sequence number
        syn:        bool        &log;   # synchronise flag
        fin:        bool        &log;   # finish flag
        rst:        bool        &log;   # reset connection flag
        len:        string      &log;   # payload length, header excludes
        first:      string      &log;   # this sequence number
        last:       string      &log;   # next (wanted) sequence number
        payload:    string      &log;   # raw bytearray type payload
    };

    redef enum Log::ID += { LOG_INFO };

    # Define a logging event. By convention, this is called
    # "log_<stream>".
    global log_info: event(info: Info);

    ## Write logs in JSON format
    const use_json: bool = T &redef;
}

@if ( use_json )
    redef LogAscii::use_json = T;
@endif

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string) {
    local flag_orig: bool = contents_orig && is_orig;
    local flag_resp: bool = contents_resp && !is_orig;

    if ( flag_orig || flag_resp ) {
        local syn: bool = "S" in flags;
        local fin: bool = "F" in flags;
        local rst: bool = "R" in flags;

        local id: conn_id = is_orig? c$id : [$orig_h=c$id$resp_h, $orig_p=c$id$resp_p,
                                             $resp_h=c$id$orig_h, $resp_p=c$id$orig_p];

        if ( syn || fin || rst || ( len > 0 ) ) {
            local info: Info = [$conn=c,
                                $is_orig=is_orig,
                                $id=id,
                                $bufid=c$uid,               # original packet identifier
                                $ack=fmt("%s", ack),        # acknowledgement
                                $dsn=fmt("%s", seq),        # data sequence number
                                $syn=syn,                   # synchronise flag
                                $fin=fin,                   # finish flag
                                $rst=rst,                   # reset connection flag
                                $len=fmt("%s", len),        # payload length, header excludes
                                $first=fmt("%s", seq),      # this sequence number
                                $last=fmt("%s", seq+len),   # next (wanted) sequence number
                                $payload=payload];          # raw bytearray type payload
            Log::write(LOG_INFO, info);
        }
    }
}

function make_name(id: Log::ID, path: string, rec: Reass::Info): string {
    local suffix: string = rec$is_orig? "orig": "resp";
    local name: string = generate_extraction_filename(rec$bufid, rec$conn, suffix);
    return fmt("%s/%s", log_prefix, name);
}

event bro_init() &priority=5 {
    # Specify the "log_info" event here in order for Bro to raise it.
    Log::create_stream(Reass::LOG_INFO, [$columns=Info, $ev=Reass::log_info, $path="reass_info"]);

    # local filter: Log::Filter = [$name="reass", $path_func=make_name];
    # Log::add_filter(Reass::LOG_INFO, filter);
}
