@load ./plugins
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

    redef enum Log::ID += { LOG_PKT };

    # Define a logging event. By convention, this is called
    # "log_<stream>".
    global log_pkt: event(pkt: pkt_t);

    ## Write logs in JSON format
    const use_json: bool = F &redef;

    ## packet dict
    type Info: record {
        bufid:      conn_id;    # original packet identifier
        ack:        count;      # acknowledgement
        dsn:        count;      # data sequence number
        syn:        bool;       # synchronise flag
        fin:        bool;       # finish flag
        rst:        bool;       # reset connection flag
        len:        count;      # payload length, header excludes
        first:      count;      # this sequence number
        last:       count;      # next (wanted) sequence number
        payload:    bytearray;  # raw bytearray type payload
    };

    ## buffer fields
    global BUFFER: buffer;
}

@if ( use_json )
    redef LogAscii::use_json = T;
@endif

global conn_table: table[conn_id] of connection;

function make_name(c: connection, ack: count &default=0): string {
    local suffix: string = fmt("%s", ack);
    local name: string = generate_extraction_filename(c$uid, c, suffix);
    return fmt("%s/%s", path, name);
}

function write_data(data: bytearray, c: connection, ack: count, is_part: bool &default=F,
                    start: count &default=0, stop: count &default=0) {
    local filename: string;
    local pkt: pkt_t;

    if ( is_part )
        filename = fmt("%s_%s-%s.part", make_name(c, ack), start, stop);
    else
        filename = fmt("%s.dat", make_name(c, ack));

    local payload: string = bytearray_to_string(data);
    local f: file = open(filename);
    write_file(f, payload);
    close(f);

    if ( is_part )
        pkt = [$id=c$id,
               $uid=c$uid,
               $ack=ack,
               $len=|payload|,
               $start=start,
               $stop=stop];
    else
        pkt = [$id=c$id,
               $uid=c$uid,
               $ack=ack,
               $len=|payload|];
    Log::write(LOG_PKT, pkt);
    print filename;
}

function submit(bufid: conn_id, c: connection) {
    # print fmt("submit: %s", bufid);
    local HDL: hdl_t = BUFFER[bufid]$hdl;
    local BUF: buf_t = BUFFER[bufid]$buf;

    local data: bytearray;
    local part: part_t;

    local index: count = 0;
    local start: count = 0;
    local stop: count = 0;
    local hole: hole_t;

    for ( ack in BUF ) {
        part = BUF[ack];
        if ( |HDL| <= 1 ) {
            data = part$raw;
            if ( |data| > 0 )
                write_data(data, c, ack);
        } else {
            print "------";
            print bufid;
            print HDL;
            print "------";

            while ( index < |HDL| ) {
                hole = HDL[index];
                stop = hole$first;
                data = bytearray_indice(part$raw, start, stop);
                if ( |data| > 0 )
                    write_data(data, c, ack, T, start, stop);
                start = hole$last;
            }
            data = bytearray_indice(part$raw, start);
            write_data(data, c, ack, T, start, |part$raw|);
        }
    }
    delete BUFFER[bufid];
}

event tcp_reassembly(info: Info, c: connection) {
    conn_table[info$bufid] = c;
    # print info;

    local BUFID: conn_id = info$bufid;  # Buffer Identifier
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
        hdl[0] = [$first=info$len, $last=0xffffffffffffffff];
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
    local TMP: bytearray;

    # record fragment payload
    local ISN: count = BUFFER[BUFID]$buf[ACK]$isn;     # Initial Sequence Number
    local RAW: bytearray = BUFFER[BUFID]$buf[ACK]$raw; # Raw Payload Data
    if ( DSN >= ISN ) {     # if fragment goes after existing payload
        LEN = BUFFER[BUFID]$buf[ACK]$len;
        SUM = ISN + LEN;
        # print DSN, ISN, LEN, SUM;
        if ( DSN >= SUM ) {     # if fragment goes after existing payload
            GAP = DSN - (ISN + LEN);        # gap length between payloads
            bytearray_extend(RAW, bytearray_new(GAP));
            bytearray_extend(RAW, info$payload);
        } else                  # if fragment partially overlaps existing payload
            bytearray_extend(RAW, info$payload, DSN-ISN);
    } else {
        LEN = info$len;
        SUM = DSN + LEN;
        # print DSN, ISN, LEN, SUM;
        if ( ISN >= SUM ) {     # if fragment exceeds existing payload
            GAP = ISN - SUM;                # gap length between payloads
            TMP = copy(info$payload);
            bytearray_extend(TMP, bytearray_new(GAP));
            bytearray_extend(TMP, RAW);
            RAW = copy(TMP);
        } else {                # if fragment partially overlaps existing payload
            TMP = copy(info$payload);
            bytearray_extend(TMP, RAW, SUM);
            RAW = copy(TMP);
        }
    }
    BUFFER[BUFID]$buf[ACK]$raw = copy(RAW); # update payload datagram
    BUFFER[BUFID]$buf[ACK]$len = |RAW|;     # update payload length

    # print |BUFFER[BUFID]$buf[ACK]$raw|, |bytearray_to_string(BUFFER[BUFID]$buf[ACK]$raw)|;
    # print BUFID;
    # # print BUFFER[BUFID];
    # print BUFFER[BUFID]$hdl;
    # for ( ack in BUFFER[BUFID]$buf ) {
    #     print BUFFER[BUFID]$buf[ack]$isn, BUFFER[BUFID]$buf[ack]$len;
    #     print bytearray_to_string(BUFFER[BUFID]$buf[ack]$raw);
    # }
    # print "--------";

    local HDL: hdl_t = copy(BUFFER[BUFID]$hdl);
    local new_hole: hole_t;
    local hole: hole_t;
    local index: count = 0;
    # print BUFID, BUFFER[BUFID]$hdl;
    while ( index < |BUFFER[BUFID]$hdl| ) {                 # step one
        hole = BUFFER[BUFID]$hdl[index];
        # print index, hole;
        if ( info$first > hole$last ) {                     # step two
            ++ index;
            next;
        }
        if ( info$last < hole$first ) {                     # step three
            ++ index;
            next;
        }
        HDL = hdl_delete(HDL, index);                       # step four
        if ( info$first > hole$first ) {                    # step five
            new_hole = [
                $first=hole$first,
                $last=info$first - 1
            ];
            hdl_insert(HDL, index, new_hole);
        }
        if ( info$last < hole$last && !FIN && !RST ) {      # step six
            new_hole = [
                $first=info$last + 1,
                $last=hole$last
            ];
            hdl_insert(HDL, index+1, new_hole);
        }
        break;                                              # step seven
    }
    BUFFER[BUFID]$hdl = copy(HDL);                          # update HDL

    # when FIN/RST is set, submit buffer of this session
    if ( FIN || RST )
        submit(BUFID, c);
    # print fmt("reassembled: %s", c$id);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) &priority=5 {
    local flag_orig: bool = contents_orig && is_orig;
    local flag_resp: bool = contents_resp && !is_orig;

    # print fmt("packet: %s", c$id);

    if ( flag_orig || flag_resp ) {
        local syn: bool = "S" in flags;
        local fin: bool = "F" in flags;
        local rst: bool = "R" in flags;

        if ( syn || fin || rst || ( len > 0 ) ) {
            local conn: connection = copy(c);
            conn$id = is_orig? c$id : [$orig_h=c$id$resp_h, $orig_p=c$id$resp_p,
                                       $resp_h=c$id$orig_h, $resp_p=c$id$orig_p];

            local info: Info = [$bufid=conn$id,                         # original packet identifier
                                $ack=ack,                               # acknowledgement
                                $dsn=seq,                               # data sequence number
                                $syn=syn,                               # synchronise flag
                                $fin=fin,                               # finish flag
                                $rst=rst,                               # reset connection flag
                                $len=len,                               # payload length, header excludes
                                $first=seq,                             # this sequence number
                                $last=seq+len,                          # next (wanted) sequence number
                                $payload=string_to_bytearray(payload)]; # raw bytearray type payload
            event tcp_reassembly(info, conn);
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
