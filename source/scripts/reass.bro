@load ./custom/buffer.bro
@load ./helpers/packet.bro
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

    ## Record all reassembled payload (even though in parts)
    const verbose_mode: bool = F &redef;

    ## Predicators of app-layer protocols
    global predicate: hook (s: string);
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
    fin:        bool;
    rst:        bool;
};

global db: table[conn_id] of table[count] of vector of context;
global en: set[string];

function frag_comp(a: context, b: context): int {
    return ( a$ts > b$ts ) ? 1 : -1;
}

function make_name(c: connection, ack: count &default=0): string {
    local suffix: string = fmt("%s", ack);
    local name: string = generate_extraction_filename(c$uid, c, suffix);
    return fmt("%s/%s", path, name);
}

function write_data(data: string, c: connection, ack: count, is_part: bool &default=F,
                    start: count &default=0, stop: count &default=0) {
    local filename: string;
    local pkt: pkt_t;

    if ( is_part )
        filename = fmt("%s_%s-%s.part", make_name(c, ack), start, stop);
    else
        filename = fmt("%s.dat", make_name(c, ack));

    local payload: string = data;
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

event tcp_reassembly(vec: vector of context, ack: count) {
    local HDL: hdl_t;       # Hole Descriptor List
    local BUF: part_t;      # Buffer

    local ISN: count;       # Initial Sequence Number
    local LEN: count;       # Fragment Length
    local RAW: string;      # Raw Payload Data

    local DSN: count;       # Data Sequence Number
    local PLD: string;      # Fragment Payload

    local SUM: count;       # SUM = ISN + LEN
    local GAP: count;       # gap length between payloads; GAP = DSN - SUM

    local sorted_vec: vector of context = sort(vec, frag_comp);
    local FLAG: bool = T; # is first fragment?

    local FIN: bool;
    local RST: bool;

    local TMP: string;
    local frag: context;
    local conn: connection;

    local first: count;         # this sequence number
    local last: count;          # next (wanted) sequence number

    local new_hole: hole_t;
    local hole: hole_t;

    for ( f in sorted_vec ) {
        frag = sorted_vec[f];
        DSN = frag$seq;
        PLD = frag$payload;
        FIN = frag$fin;
        RST = frag$rst;

        # initialise buffers with first fragment
        if ( FLAG ) {
            BUF = [$isn=DSN, $len=frag$len, $raw=PLD];
            ISN = DSN;
            FLAG = F;

            add HDL[[$first=frag$len, $last=0xffffffffffffffff]];
            conn = frag$conn;
            next;
        }

        ISN = BUF$isn;
        RAW = BUF$raw;
        if ( DSN >= ISN ) {     # if fragment goes after existing payload
            LEN = BUF$len;
            SUM = ISN + LEN;
            if ( DSN >= SUM ) {     # if fragment goes after existing payload
                GAP = DSN - SUM;                # gap length between payloads
                RAW += string_fill(GAP, "\x00") + PLD;
            } else                  # if fragment partially overlaps existing payload
                RAW = RAW[:DSN-ISN] + PLD;
        } else {
            LEN = frag$len;
            SUM = DSN + LEN;
            if ( ISN >= SUM ) {     # if fragment exceeds existing payload
                GAP = ISN - SUM;                # gap length between payloads
                RAW = PLD + string_fill(GAP, "\x00") + RAW;
            } else                  # if fragment partially overlaps existing payload
                RAW = PLD[:SUM] + RAW;
        }
        BUF$raw = copy(RAW);
        BUF$len = |RAW|;

        first = frag$seq;
        last = first + frag$len;
        for ( hole in HDL ) {                           # step one
            if ( first > hole$last )                    # step two
                next;
            if ( last < hole$first )                    # step three
                next;
            delete HDL[hole];                           # step four
            if ( first > hole$first ) {                 # step five
                new_hole = [$first=hole$first,
                            $last=first - 1];
                add HDL[new_hole];
            }
            if ( last < hole$last && !FIN && !RST ) {   # step six
                new_hole = [$first=last + 1,
                            $last=hole$last];
                add HDL[new_hole];
            }
            break;                                      # step seven
        }
    }

    local start: count = 0;
    local stop: count = 0;

    local data: string;
    if ( ( |HDL| > 1 ) && verbose_mode ) {
        for ( hole in HDL ) {
            stop = hole$first;
            data = BUF$raw[start:stop];
            if ( |data| > 0 )
                write_data(data, conn, ack, T, start, stop);
            start = hole$last;
        }
        data = BUF$raw[start:];
        if ( |data| > 0 )
            write_data(data, conn, ack, T, start, |BUF$raw|);
    } else {
        data = BUF$raw;
        if ( |data| > 0 )
            write_data(data, conn, ack);
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
    local uid: string = c$uid;
    if ( uid !in en && hook predicate(payload) )
        add en[uid];

    if ( uid in en ) {
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
                                      $payload=payload,
                                      $fin=fin,
                                      $rst=rst];

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
}

event bro_init() &priority=5 {
    # Specify the "log_pkt" event here in order for Bro to raise it.
    Log::create_stream(Reass::LOG_PKT, [$columns=pkt_t, $ev=Reass::log_pkt, $path="reass_pkt"]);
}

event bro_done() {
    for ( id in db )
        submit(id);
}
