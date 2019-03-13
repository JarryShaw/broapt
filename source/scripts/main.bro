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

    ## Write logs in JSON format
    const use_json: bool = F &redef;

    ## packet dict
    type Info: record {
        conn:       connection;
        bufid:      string;     # original packet identifier
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
    global BUF: buffer;
}

@if ( use_json )
    redef LogAscii::use_json = T;
@endif

event submit(bufid: string, c: connection) {
    # print fmt("submit: %s", bufid);

    delete BUF[bufid];
}

event tcp_reassembly(info: Info) {

    local BUFID: string = info$bufid;   # Buffer Identifier
    local DSN: count = info$dsn;        # Data Sequence Number
    local ACK: count = info$ack;        # Acknowledgement Number
    local SYN: bool = info$syn;         # Synchronise Flag (Establishment)
    local FIN: bool = info$fin;         # Finish Flag (Termination)
    local RST: bool = info$rst;         # Reset Connection Flag (Termination)

    # when SYN is set, reset buffer of this session
    if ( SYN && BUFID in BUF )
        event submit(BUFID, info$conn);

    # initialise buffer with BUFID & ACK
    if ( BUFID !in BUF ) {
        local hdl: hdl_t;
        local buf: buf_t;
        hdl += [$first=info$len, $last=0xffffffffffffffff];
        buf[ACK] = [
            $isn=info$dsn,
            $len=info$len,
            $raw=info$payload
        ];
        BUF[BUFID] = [$hdl=hdl, $buf=buf];
    }

    # initialise buffer with ACK
    if ( ACK !in BUF[BUFID]$buf )
        BUF[BUFID]$buf[ACK] = [
            $isn=info$dsn,
            $len=info$len,
            $raw=info$payload
        ];

    local GAP: count;
    local SUM: count;

    local LEN: count;
    local TMP: bytearray;

    # record fragment payload
    local ISN: count = BUF[BUFID]$buf[ACK]$isn;     # Initial Sequence Number
    local RAW: bytearray = BUF[BUFID]$buf[ACK]$raw; # Raw Payload Data
    if ( DSN >= ISN ) {     # if fragment goes after existing payload
        LEN = BUF[BUFID]$buf[ACK]$len;
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
    BUF[BUFID]$buf[ACK]$raw = copy(RAW);    # update payload datagram
    BUF[BUFID]$buf[ACK]$len = |RAW|;        # update payload length
    # print BUF[BUFID];

    local HDL: hdl_t = copy(BUF[BUFID]$hdl);
    local new_hole: hole_t;
    local index: count = 0;
    local hole: hole_t;
    while ( index < |BUF[BUFID]$hdl| ) {                    # step one
        hole = BUF[BUFID]$hdl[index];
        if ( info$first > hole$last ) {                     # step two
            ++ index;
            next;
        }
        if ( info$last < hole$first ) {                     # step three
            ++ index;
            next;
        }
        HDL = vector_delete(HDL, index);                    # step four
        if ( info$first > hole$first ) {                    # step five
            new_hole = [
                $first=hole$first,
                $last=info$first - 1
            ];
            vector_insert(HDL, index, new_hole);
        }
        if ( info$last < hole$last && !FIN && !RST ) {      # step six
            new_hole = [
                $first=info$last + 1,
                $last=hole$last
            ];
            vector_insert(HDL, index+1, new_hole);
        }
        break;                                              # step seven
    }
    BUF[BUFID]$hdl = copy(HDL);                             # update HDL

    # when FIN/RST is set, submit buffer of this session
    if ( FIN || RST )
        event submit(BUFID, info$conn);
    # print fmt("reassembled: %s", info$conn$id);
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

            local info: Info = [$conn=conn,
                                $bufid=c$uid,                           # original packet identifier
                                $ack=ack,                               # acknowledgement
                                $dsn=seq,                               # data sequence number
                                $syn=syn,                               # synchronise flag
                                $fin=fin,                               # finish flag
                                $rst=rst,                               # reset connection flag
                                $len=len,                               # payload length, header excludes
                                $first=seq,                             # this sequence number
                                $last=seq+len,                          # next (wanted) sequence number
                                $payload=string_to_bytearray(payload)]; # raw bytearray type payload
            event tcp_reassembly(info);
        }
    }
}
