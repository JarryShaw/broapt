@load ./vendor/files
@load ./vendor/json
@load ./vendor/paths
# @load misc/dump-events

module Reass;

export {
    ## Path to store logs
    const log_prefix: string = "logs" &redef;
    ## Path to store reassembled payloads
    const pld_prefix: string = "contents" &redef;
    ## Path to C/C++ TCP reassembly implementation executable
    const exec_path: string = "build/reass" &redef;

    ## Record TCP content from originator-side
    const contents_orig: bool = T &redef;
    ## Record TCP content from responder-side
    const contents_resp: bool = T &redef;

    ## Write logs in JSON format
    const use_json: bool = F &redef;

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

    type pkt_t: record {
        ts:         time    &log;
        uid:        string  &log;
        id:         conn_id &log;
        is_orig:    bool    &log;
        ack:        count   &log;
    };

    ## Predicators of app-layer protocols
    global predicate: hook (s: string, pkt: pkt_t);
}

@ifndef ( BRO_LOG_SUFFIX )
    const BRO_LOG_SUFFIX: string = getenv("BRO_LOG_SUFFIX");
@endif

const log_suffix: string = ( BRO_LOG_SUFFIX != "" ) ? BRO_LOG_SUFFIX : ".log";

type context: record {
    ts:         time    &log;
    seq:        count   &log;
    len:        count   &log;
    fin_rst:    bool;
    payload:    string  &log;
};

global en: table[string] of set[count];
global ex: table[string] of set[count];

function write_json(name: string, info: context) {
    local f: file = open_for_append(cat(name, log_suffix));
    local data: string = cat(to_json(info), "\n");
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
    local f: file = open_for_append(cat(name, log_suffix));
    local data: string = cat(info$ts, separator,
                             info$seq, separator,
                             info$len, separator,
                             info$fin_rst, separator,
                             ( info$len == 0 ) ? empty_field : info$payload, "\n");
    write_file(f, data);
    close(f);
}

function init_text(name: string) {
    local f: file = open(cat(name, log_suffix));
    write_file(f, fmt("#separator %s\n", to_hex(separator)));
    write_file(f, fmt("#set_separator%s%s\n", separator, set_separator));
    write_file(f, fmt("#empty_field%s%s\n", separator, empty_field));
    write_file(f, fmt("#unset_field%s%s\n", separator, unset_field));
    write_file(f, fmt("#path%s%s\n", separator, name));
    write_file(f, fmt("#open%s%s\n", separator, strftime("%Y-%m-%d-%H-%M-%S", current_time())));
    write_file(f, fmt("#fields%sts%sseq%slen%sfin_rst%spayload\n",
                    separator, separator, separator, separator, separator));
    write_file(f, fmt("#types%stime%scount%scount%sbool%sstring\n",
                    separator, separator, separator, separator, separator));
    close(f);
}

function make_name(c: connection, ack: count &default=0): string {
    local suffix: string = fmt("%s", ack);
    local name: string = generate_extraction_filename(c$uid, c, suffix);
    return build_path(log_prefix, name);
}

event process_tcp_packet(c: connection, is_orig: bool, flags: string,
                         seq: count, ack: count, len: count, payload: string) {
    local new_file: bool = F;
    local uid: string = fmt("%s-%s", c$uid, is_orig ? "orig" : "resp");
    if ( uid !in en )
        en[uid] = set();
    if ( uid !in ex )
        ex[uid] = set();
    if ( ( ( ack !in en[uid] ) && ( ack !in ex[uid] ) ) && ( len > 0 ) ) {
        local pkt: pkt_t = [$ts=network_time(),
                            $id=c$id,
                            $is_orig=is_orig,
                            $uid=c$uid,
                            $ack=ack];
        if ( hook predicate(payload, pkt) ) {
            add en[uid][ack];
            new_file = T;
        } else
            add ex[uid][ack];
    }

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
            if ( new_file && !use_json )
                init_text(name);

            local frag: context = [$ts=network_time(),
                                    $seq=seq,
                                    $len=len,
                                    $fin_rst=(fin || rst),
                                    $payload=bytestring_to_hexstr(payload)];
            use_json ? write_json(name, frag) : write_text(name, frag);
        }
    }
}

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string) &priority=5 {
    local flag_orig: bool = contents_orig && is_orig;
    local flag_resp: bool = contents_resp && !is_orig;

    if ( flag_orig || flag_resp )
        event process_tcp_packet(c, is_orig, flags, seq, ack, len, payload);
}

event subprocess(name: string, line: string) {
    local args: string = fmt("for file in $(ls %s 2>/dev/null); do echo '%s' >> ${file}; %s ${file} \"%s/$(basename ${file} '%s')\" &; done",
                             str_shell_escape(name), line, str_shell_escape(exec_path), str_shell_escape(pld_prefix), log_suffix);
    system(args);
}

event process_connection_end(c: connection) {
    local name: string;
    local line: string = fmt("#close%s%s", separator, strftime("%Y-%m-%d-%H-%M-%S", current_time()));

    local orig: string = fmt("%s-orig", c$uid);
    if ( ( orig in en ) || ( orig in ex ) ) {
        if ( !use_json ) {
            name = build_path(log_prefix, generate_extraction_filename(c$uid, c, cat("*", log_suffix)));
            event subprocess(name, line);
        }

        delete en[orig];
        delete ex[orig];
    }

    local resp: string = fmt("%s-resp", c$uid);
    if ( ( resp in en ) || ( resp in ex ) ) {
        if ( !use_json ) {
            local conn: connection = [$id=[$orig_h=c$id$resp_h, $orig_p=c$id$resp_p,
                                            $resp_h=c$id$orig_h, $resp_p=c$id$orig_p],
                                        $orig=c$resp,
                                        $resp=c$orig,
                                        $start_time=c$start_time,
                                        $duration=c$duration,
                                        $service=c$service,
                                        $history=c$history,
                                        $uid=c$uid];

            name = build_path(log_prefix, generate_extraction_filename(c$uid, conn, cat("*", log_suffix)));
            event subprocess(name, line);
        }

        delete en[resp];
        delete ex[resp];
    }
}

event connection_state_remove(c: connection) &priority=5 {
    if ( get_port_transport_proto(c$id$orig_p) == tcp )
        event process_connection_end(c);
}

event bro_done() &priority=5 {
    local uids: set[string];
    for ( uid in en )
        add uids[split_string1(uid, /-/)[0]];
    for ( uid in ex )
        add uids[split_string1(uid, /-/)[0]];

    if ( !use_json ) {
        local name: string;
        local line: string = fmt("#close%s%s", separator, strftime("%Y-%m-%d-%H-%M-%S", current_time()));

        for ( uid in uids ) {
            name = build_path(log_prefix, fmt("%s_%s", uid, log_suffix));
            event subprocess(name, line);
        }
    }
}
