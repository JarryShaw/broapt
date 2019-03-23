@load base/utils/files
@load base/utils/json
# @load misc/dump-events

module Reass;

export {
    ## Path to store logs
    const log_prefix: string = "logs" &redef;

    ## Record TCP content from originator-side
    const contents_orig: bool = T &redef;
    ## Record TCP content from responder-side
    const contents_resp: bool = T &redef;

    ## Write logs in JSON format
    const use_json: bool = T &redef;

    ## Default separator to use between fields.
    ## Individual writers can use a different value.
    const separator = "\t" &redef;

    ## Default separator to use between elements of a set.
    ## Individual writers can use a different value.
    const set_separator = "," &redef;

    ## Default string to use for empty fields. This should be different
    ## from *unset_field* to make the output unambiguous.
    ## Individual writers can use a different value.
    const empty_field = "(empty)" &redef;

    ## Default string to use for an unset &optional field.
    ## Individual writers can use a different value.
    const unset_field = "-" &redef;

    ## Predicators of app-layer protocols
    global predicate: hook (s: string);
}

type context: record {
    ts:         time    &log;
    seq:        count   &log;
    len:        count   &log;
    payload:    string  &log;
};

global db: set[string];
global en: table[string] of set[count];
global ex: table[string] of set[count];

function write_json(name: string, info: context) {
    local f: file;
    if ( name in db )
        f = open_for_append(fmt("%s.log", name));
    else {
        add db[name];
        f = open(fmt("%s.log", name));
    }
    local data: string = fmt("%s\n", to_json(info));
    write_file(f, data);
    close(f);
}

function to_hex(s: string &default=empty_field): string {
    local ret: string = "";
    for ( char in s ) {
        ret += fmt("\\x%s", bytestring_to_hexstr(char));
    }
    return ret;
}

function write_text(name: string, info: context) {
    local f: file;
    if ( name in db )
        f = open_for_append(fmt("%s.log", name));
    else {
        add db[name];
        f = open(fmt("%s.log", name));
        write_file(f, fmt("#separator %s\n", to_hex(separator)));
        write_file(f, fmt("#set_separator%s%s\n", separator, set_separator));
        write_file(f, fmt("#empty_field%s%s\n", separator, empty_field));
        write_file(f, fmt("#unset_field%s%s\n", separator, unset_field));
        write_file(f, fmt("#path%s%s\n", separator, name));
        write_file(f, fmt("#fields%sts%sseq%slen%spayload\n",
                        separator, separator, separator, separator));
        write_file(f, fmt("#types%stime%scount%scount%sstring\n",
                        separator, separator, separator, separator));
    }
    local data: string = fmt("%s%s%s%s%s%s%s\n",
                             info$ts, separator,
                             info$seq, separator,
                             info$len, separator,
                             ( info$len == 0 ) ? empty_field : info$payload);
    write_file(f, data);
    close(f);
}

function make_name(c: connection, ack: count &default=0): string {
    local suffix: string = fmt("%s", ack);
    local name: string = generate_extraction_filename(c$uid, c, suffix);
    return fmt("%s/%s", log_prefix, name);
}

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string) {
    local flag_orig: bool = contents_orig && is_orig;
    local flag_resp: bool = contents_resp && !is_orig;

    if ( flag_orig || flag_resp ) {
        local uid: string = fmt("%s-%s", c$uid, is_orig ? "orig" : "resp");
        if ( uid !in en )
            en[uid] = set();
        if ( uid !in ex )
            ex[uid] = set();
        if ( ( ( ack !in en[uid] ) && ( ack !in ex[uid] ) ) && ( len > 0 ) )
            if ( hook predicate(payload) )
                add en[uid][ack];
            else
                add ex[uid][ack];

        if ( ack in en[uid] ) {
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

                local name: string = make_name(conn, ack);
                local pkt: context = [$ts=network_time(),
                                      $seq=seq,
                                      $len=len,
                                      $payload=bytestring_to_hexstr(payload)];
                use_json ? write_json(name, pkt) : write_text(name, pkt);

                if ( fin || rst ) {
                    print name;
                    delete en[uid];
                    delete ex[uid];
                    delete db[name];
                }
            }
        }
    }
}
