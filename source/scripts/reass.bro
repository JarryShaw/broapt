@load ./helpers
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

    ## Record all reassembled payload (even though in parts)
    const strict_mode: bool = F &redef;

    ## Predicators of app-layer protocols
    # const predicator: set[function] &redef;
}

type fragment: record {
    isn:    count;
    len:    count;
    raw:    string;
};

type context: record {
    conn:       connection; # Bro connection instance
    ts:         time;       # timestamp
    seq:        count;      # data sequence number
    len:        count;      # payload length, header excludes
    payload:    string;     # raw bytearray type payload
};

global db: table[conn_id] of table[count] of vector of context;

function frag_comp(a: context, b: context): int {
    return ( a$ts > b$ts ) ? 1 : -1;
}

function make_name(c: connection, ack: count &default=0): string {
    local suffix: string = fmt("%s", ack);
    local name: string = generate_extraction_filename(c$uid, c, suffix);
    return fmt("%s/%s", path, name);
}

event write_data(data: bytearray, c: connection, ack: count, is_part: bool &default=F,
                 start: count &default=0, stop: count &default=0) {
    local filename: string;
    if ( is_part )
        filename = fmt("%s_%s-%s.part", make_name(c, ack), start, stop);
    else
        filename = fmt("%s.dat", make_name(c, ack));

    local payload: string = bytearray_to_string(data);
    local f: file = open(filename);

    write_file(f, payload);
    close(f);
    print filename;
}

event tcp_reassembly(vec: vector of context, ack: count) {
    local HDL: hdl_t;           # Hole Descriptor List
    local BUF: part_t;          # Buffer

    local ISN: count;           # Initial Sequence Number
    local LEN: count;           # Fragment Length
    local RAW: bytearray;       # Raw Payload Data

    local DSN: count;           # Data Sequence Number
    local PLD: bytearray;       # Fragment Payload

    local SUM: count;           # SUM = ISN + LEN
    local GAP: count;           # gap length between payloads; GAP = DSN - SUM

    local sorted_vec: vector of context = sort(vec, frag_comp);
    local FLAG_FIRST: bool = T; # is first fragment?

    local VEC_LAST: count = |vec| - 1;
    local FLAG_LAST: bool = F;  # is last fragment?

    local TMP: bytearray;
    local conn: connection;

    local index: count = 0;
    local first: count;         # this sequence number
    local last: count;          # next (wanted) sequence number

    local new_hole: hole_t;
    local hole: hole_t;

    for ( f in sorted_vec ) {
        print fmt("f: %s", f);
        DSN = sorted_vec[f]$seq;
        PLD = string_to_bytearray(sorted_vec[f]$payload);

        # initialise buffers with first fragment
        if ( FLAG_FIRST ) {
            HDL[0] = [$first=sorted_vec[f]$len, $last=0xffffffffffffffff];
            BUF = [$isn=DSN, $len=sorted_vec[f]$len, $raw=PLD];
            ISN = DSN;

            conn = sorted_vec[f]$conn;
            FLAG_FIRST = F;
            next;
        }

        ISN = BUF$isn;
        RAW = BUF$raw;
        if ( DSN >= ISN ) {     # if fragment goes after existing payload
            LEN = BUF$len;
            SUM = ISN + LEN;
            if ( DSN >= SUM ) {     # if fragment goes after existing payload
                GAP = DSN - SUM;                # gap length between payloads
                bytearray_extend(RAW, bytearray_new(GAP));
                bytearray_extend(RAW, PLD);
            } else                  # if fragment partially overlaps existing payload
                bytearray_extend(RAW, PLD, DSN-ISN);
        } else {
            LEN = sorted_vec[f]$len;
            SUM = DSN + LEN;
            if ( ISN >= SUM ) {     # if fragment exceeds existing payload
                GAP = ISN - SUM;                # gap length between payloads
                TMP = copy(PLD);
                bytearray_extend(TMP, bytearray_new(GAP));
                bytearray_extend(TMP, RAW);
                RAW = copy(TMP);
            } else {                # if fragment partially overlaps existing payload
                TMP = copy(PLD);
                bytearray_extend(TMP, RAW, SUM);
                RAW = copy(TMP);
            }
        }
        BUF$raw = copy(RAW);
        BUF$len = |RAW|;

        first = sorted_vec[f]$seq;
        last = first + sorted_vec[f]$len;
        while ( index < |HDL| ) {                       # step one
            print fmt("index: %s", index);
            hole = HDL[index];
            if ( first > hole$last ) {                  # step two
                ++ index;
                next;
            }
            if ( last < hole$first ) {                  # step three
                ++ index;
                next;
            }
            HDL = hdl_delete(HDL, index);               # step four
            if ( first > hole$first ) {                 # step five
                new_hole = [$first=hole$first,
                            $last=first - 1];
                hdl_insert(HDL, index, new_hole);
            }
            FLAG_LAST = f < VEC_LAST;
            if ( last < hole$last && FLAG_LAST ) {      # step six
                new_hole = [$first=last + 1,
                            $last=hole$last];
                hdl_insert(HDL, index + 1, new_hole);
            }
            break;                                      # step seven
        }
    }

    local start: count = 0;
    local stop: count = 0;

    local data: bytearray;
    if ( ( |HDL| > 1 ) && strict_mode ) {
        for ( h in HDL ) {
            hole = HDL[h];
            stop = hole$first;
            data = bytearray_indice(BUF$raw, start, stop);
            if ( |data| > 0 )
                event write_data(data, conn, ack, T, start, stop);
            start = hole$last;
        }
        data = bytearray_indice(BUF$raw, start);
        if ( |data| > 0 )
            event write_data(data, conn, ack, T, start, |BUF$raw|);
    } else {
        data = BUF$raw;
        if ( |data| > 0 )
            event write_data(data, conn, ack);
    }
}

function submit(id: conn_id) {
    print id;

    for ( ack in db[id] )
        event tcp_reassembly(db[id][ack], ack);

    delete db[id];
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
            c$id = id;

            local pkt: context = [$conn=c,
                                  $ts=network_time(),
                                  $seq=seq,
                                  $len=len,
                                  $payload=payload];

            if ( syn && ( id in db ) )
                submit(id);

            if ( id in db ) {
                if ( ack in db[id] )
                    db[id][ack] += pkt;
                else
                    db[id][ack] = vector(pkt);
            } else
                db[id] = table([ack] = vector(pkt));

            if ( fin || rst )
                submit(id);
        }
    }
}

event bro_done() {
    for ( id in db )
        submit(id);
}
