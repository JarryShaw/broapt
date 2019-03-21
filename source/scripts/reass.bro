# @load misc/dump-events

module Reass;

export {
    ## Reassemble TCP content from originator-side
    const contents_orig: bool = T &redef;
    ## Reassemble TCP content from responder-side
    const contents_resp: bool = T &redef;
}

type Fragment: record {
    dsn:        count;      # data sequence number
    syn:        bool;       # synchronise flag
    fin:        bool;       # finish flag
    rst:        bool;       # reset connection flag
    len:        count;      # payload length, header excludes
    payload:    string;     # raw bytearray type payload
};

global buffer: table[conn_id] of table[count] of set[Fragment];

function commit(id: conn_id) {
    print id;
    delete buffer[id];
}

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string) &priority=5 {
    local flag_orig: bool = contents_orig && is_orig;
    local flag_resp: bool = contents_resp && !is_orig;

    if ( flag_orig || flag_resp ) {
        local syn: bool = "S" in flags;
        local fin: bool = "F" in flags;
        local rst: bool = "R" in flags;

        if ( syn || fin || rst || ( len > 0 ) ) {
            local id: conn_id = [$orig_h=is_orig ? c$id$orig_h : c$id$resp_h,
                                 $orig_p=is_orig ? c$id$orig_p : c$id$resp_p,
                                 $resp_h=is_orig ? c$id$resp_h : c$id$orig_h,
                                 $resp_p=is_orig ? c$id$resp_p : c$id$orig_p];

            local pkt: Fragment = [$dsn=seq,
                                   $syn=syn,
                                   $fin=fin,
                                   $rst=rst,
                                   $len=len,
                                   $payload=payload];

            if ( id in buffer )
                if ( ack in buffer[id] )
                    add buffer[id][ack][pkt];
                else
                    buffer[id][ack] = set(pkt);
            else
                buffer[id] = table([ack] = set(pkt));

            if ( fin || rst )
                commit(id);
        }
    }
}

event bro_done() {
    for ( id in buffer )
        commit(id);
}
