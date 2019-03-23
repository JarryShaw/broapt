@load ./custom
@load base/utils/files
# @load misc/dump-events

module Reass;

export {
    ## Path to store files
    const path: string = "contents" &redef;

    ## Reassemble TCP content from originator-side
    const contents_orig: bool = T &redef;
    ## Reassemble TCP content from responder-side
    const contents_resp: bool = T &redef;

    redef enum Log::ID += { LOG_PKT };

    # Define a logging event. By convention, this is called
    # "log_<stream>".
    global log_pkt: event(pkt: pkt_t);

    ## Record all reassembled payload (even though partial)
    const verbose_mode: bool = F &redef;

    ## Predicators of app-layer protocols
    global predicate: hook (s: string);
}

## packet dict
type Info: record {
    bufid:      string;     # original packet identifier
    ack:        count;      # acknowledgement
    dsn:        count;      # data sequence number
    syn:        bool;       # synchronise flag
    fin:        bool;       # finish flag
    rst:        bool;       # reset connection flag
    len:        count;      # payload length, header excludes
    first:      count;      # this sequence number
    last:       count;      # next (wanted) sequence number
    payload:    string;     # raw bytearray type payload
};

## buffer fields
global BUFFER: buffer;
## connection mappings
global conn_table: table[string] of connection;
## connection enabled reassembly
global conn_entabled: set[string];

function make_name(c: connection, ack: count &default=0): string {
    local suffix: string = fmt("%s", ack);
    local name: string = generate_extraction_filename(c$uid, c, suffix);
    return fmt("%s/%s", path, name);
}

event write_data(data: string, c: connection,
                 ack: count, is_part: bool &default=F,
                 start: count &default=0, stop: count &default=0) {
    local filename: string;
    local pkt: pkt_t;

    if ( is_part )
        filename = fmt("%s_%s-%s.part", make_name(c, ack), start, stop);
    else
        filename = fmt("%s.dat", make_name(c, ack));

    local f: file = open(filename);
    write_file(f, data);
    close(f);

    if ( is_part )
        pkt = [$id=c$id,
               $uid=c$uid,
               $ack=ack,
               $len=|data|,
               $start=start,
               $stop=stop];
    else
        pkt = [$id=c$id,
               $uid=c$uid,
               $ack=ack,
               $len=|data|];
    Log::write(LOG_PKT, pkt);
    print filename;
}

function submit(bufid: string, c: connection) {
    # print fmt("submit: %s", bufid);
    local HDL: hdl_t = BUFFER[bufid]$hdl;
    local BUF: buf_t = BUFFER[bufid]$buf;

    local data: string;
    local part: part_t;

    local start: count = 0;
    local stop: count = 0;

    local sorted_hdl: vector of hole_t;
    local hole: hole_t;

    for ( ack in BUF ) {
        part = BUF[ack];
        if ( |HDL| > 1 && verbose_mode ) {
            sorted_hdl = sort_hdl(HDL);
            for ( index in sorted_hdl ) {
                hole = sorted_hdl[index];
                stop = hole$first;
                data = part$raw[start:stop];
                if ( |data| > 0 )
                    event write_data(data, c, ack, T, start, stop);
                start = hole$last;
            }
            data = part$raw[start:];
            if ( |data| > 0 )
                event write_data(data, c, ack, T, start, |part$raw|);
        } else {
            data = part$raw;
            if ( |data| > 0 )
                event write_data(data, c, ack);
        }
    }
    delete BUFFER[bufid];
    delete conn_table[bufid];
}

event tcp_reassembly(info: Info, c: connection) {
    local BUFID: string = info$bufid;   # Buffer Identifier
    local DSN: count = info$dsn;        # Data Sequence Number
    local ACK: count = info$ack;        # Acknowledgement Number
    local SYN: bool = info$syn;         # Synchronise Flag (Establishment)
    local FIN: bool = info$fin;         # Finish Flag (Termination)
    local RST: bool = info$rst;         # Reset Connection Flag (Termination)

    # when SYN is set, reset buffer of this session
    if ( SYN && BUFID in BUFFER )
        submit(BUFID, c);

    # initialise buffer with BUFID & ACK
    if ( BUFID !in BUFFER ) {
        local hdl: hdl_t;
        local buf: buf_t;
        add hdl[[$first=info$len, $last=0xffffffffffffffff]];
        buf[ACK] = [
            $isn=info$dsn,
            $len=info$len,
            $raw=info$payload
        ];
        BUFFER[BUFID] = [$hdl=hdl, $buf=buf];
    }

    # initialise buffer with ACK
    if ( ACK !in BUFFER[BUFID]$buf )
        BUFFER[BUFID]$buf[ACK] = [
            $isn=info$dsn,
            $len=info$len,
            $raw=info$payload
        ];

    local GAP: count;
    local SUM: count;
    local LEN: count;
    local PLD: string = info$payload;

    # record fragment payload
    local ISN: count = BUFFER[BUFID]$buf[ACK]$isn;      # Initial Sequence Number
    local RAW: string = BUFFER[BUFID]$buf[ACK]$raw;     # Raw Payload Data
    if ( DSN >= ISN ) {     # if fragment goes after existing payload
        LEN = BUFFER[BUFID]$buf[ACK]$len;
        SUM = ISN + LEN;
        # print DSN, ISN, LEN, SUM;
        if ( DSN >= SUM ) {     # if fragment goes after existing payload
            GAP = DSN - SUM;                # gap length between payloads
            RAW += string_fill(GAP, "\x00") + PLD;
        } else                  # if fragment partially overlaps existing payload
            RAW = RAW[:DSN-ISN] + PLD;
    } else {
        LEN = info$len;
        SUM = DSN + LEN;
        # print DSN, ISN, LEN, SUM;
        if ( ISN >= SUM ) {     # if fragment exceeds existing payload
            GAP = ISN - SUM;                # gap length between payloads
            RAW = PLD + string_fill(GAP, "\x00") + RAW;
        } else {                # if fragment partially overlaps existing payload
            RAW = PLD[:SUM] + RAW;
        }
    }
    BUFFER[BUFID]$buf[ACK]$raw = RAW;       # update payload datagram
    BUFFER[BUFID]$buf[ACK]$len = |RAW|;     # update payload length

    local HDL: hdl_t = copy(BUFFER[BUFID]$hdl);
    local new_hole: hole_t;
    for ( hole in BUFFER[BUFID]$hdl ) {                     # step one
        if ( info$first > hole$last )                       # step two
            next;
        if ( info$last < hole$first )                       # step three
            next;
        delete HDL[hole];                                   # step four
        if ( info$first > hole$first ) {                    # step five
            new_hole = [$first=hole$first,
                        $last=info$first - 1];
            add HDL[new_hole];
        }
        if ( info$last < hole$last && !FIN && !RST ) {      # step six
            new_hole = [$first=info$last + 1,
                        $last=hole$last];
            add HDL[new_hole];
        }
        break;                                              # step seven
    }
    BUFFER[BUFID]$hdl = copy(HDL);                          # update HDL

    # when FIN/RST is set, submit buffer of this session
    if ( FIN || RST )
        submit(BUFID, c);
}

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string) &priority=5 {
    local uid: string = fmt("%s-%s", c$uid, is_orig ? "orig" : "resp");
    if ( ( uid !in conn_entabled ) && ( len > 0 ) && hook predicate(payload) )
        add conn_entabled[uid];

    if ( uid in conn_entabled ) {
        local flag_orig: bool = contents_orig && is_orig;
        local flag_resp: bool = contents_resp && !is_orig;

        if ( flag_orig || flag_resp ) {
            local syn: bool = "S" in flags;
            local fin: bool = "F" in flags;
            local rst: bool = "R" in flags;

            if ( syn || fin || rst || ( len > 0 ) ) {
                local id: conn_id = is_orig ? c$id : [$orig_h=c$id$resp_h, $orig_p=c$id$resp_p,
                                                      $resp_h=c$id$orig_h, $resp_p=c$id$orig_p];
                local orig: endpoint = is_orig ? c$orig : c$resp;
                local resp: endpoint = is_orig ? c$resp : c$orig;
                local conn: connection = [$id=id,
                                          $orig=orig,
                                          $resp=resp,
                                          $start_time=c$start_time,
                                          $duration=c$duration,
                                          $service=c$service,
                                          $history=c$history,
                                          $uid=c$uid];

                local info: Info = [$bufid=uid,         # original packet identifier
                                    $ack=ack,           # acknowledgement
                                    $dsn=seq,           # data sequence number
                                    $syn=syn,           # synchronise flag
                                    $fin=fin,           # finish flag
                                    $rst=rst,           # reset connection flag
                                    $len=len,           # payload length, header excludes
                                    $first=seq,         # this sequence number
                                    $last=seq+len,      # next (wanted) sequence number
                                    $payload=payload];  # raw bytearray type payload

                conn_table[info$bufid] = conn;
                event tcp_reassembly(info, conn);

                if ( fin || rst )
                    delete conn_entabled[uid];
            }
        }
    }
}

event bro_init() &priority=5 {
    # Specify the "log_pkt" event here in order for Bro to raise it.
    Log::create_stream(Reass::LOG_PKT, [$columns=pkt_t, $ev=Reass::log_pkt, $path="reass_pkt"]);
}

event bro_done() {
    for ( BUFID in BUFFER )
        submit(BUFID, conn_table[BUFID]);
}
