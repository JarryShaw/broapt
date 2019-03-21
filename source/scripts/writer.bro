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
}

global file_list: set[string];

type Info: record {
    filename:   string;
    ack:        count;
    seq:        count;
    syn:        bool;
    fin:        bool;
    rst:        bool;
    len:        count;
    first:      count;
    last:       count;
    payload:    string;
};

function make_name(c: connection, is_orig: bool): string {
    local suffix: string = is_orig? "orig": "resp";
    local name: string = generate_extraction_filename(c$uid, c, suffix);
    return fmt("%s/%s", log_prefix, name);
}

function to_hex(s: string &default=empty_field): string {
    local ret: string = "";
    for ( char in s ) {
        ret += fmt("\\x%s", bytestring_to_hexstr(char));
    }
    return ret;
}

function bool_to_string(b: bool &default=F): string {
    return b ? "true" : "false";
}

function write_json(info: Info) {
    local f: file;
    if ( info$filename in file_list )
        f = open_for_append(fmt("%s.log", info$filename));
    else {
        add file_list[info$filename];
        f = open(fmt("%s.log", info$filename));
    }
    local data: string = fmt("{\"ts\": %s, \"ack\": %s, \"dsn\": %s, \"syn\": %s, \"fin\": %s, \"rst\": %s, \"len\": %s, \"first\": %s, \"last\": %s, \"payload\": \"%s\"}\n",
                             network_time(), info$ack, info$seq, bool_to_string(info$syn), bool_to_string(info$fin), bool_to_string(info$rst), info$len, info$first, info$last, bytestring_to_hexstr(info$payload));
    write_file(f, data);
    close(f);
}

function write_text(info: Info) {
    local f: file;
    if ( filename in file_list )
        f = open_for_append(fmt("%s.log", filename));
    else {
        add file_list[filename];
        f = open(fmt("%s.log", filename));
        write_file(f, fmt("#separator %s\n", to_hex(separator)));
        write_file(f, fmt("#set_separator%s%s\n", separator, set_separator));
        write_file(f, fmt("#empty_field%s%s\n", separator, empty_field));
        write_file(f, fmt("#unset_field%s%s\n", separator, unset_field));
        write_file(f, fmt("#path%s%s\n", separator, filename));
        write_file(f, fmt("#fields%sts%sack%sdsn%ssyn%sfin%srst%slen%sfirst%slast%spayload\n",
                        separator, separator, separator, separator, separator,
                        separator, separator, separator, separator, separator));
        write_file(f, fmt("#types%stime%scount%scount%sbool%sbool%sbool%scount%scount%scount%sstring\n",
                        separator, separator, separator, separator, separator,
                        separator, separator, separator, separator, separator));
    }
    write_file(f, fmt("%s%s", network_time(), separator));
    write_file(f, fmt("%s%s", info$ack, separator));
    write_file(f, fmt("%s%s", info$seq, separator));
    write_file(f, fmt("%s%s", info$syn, separator));
    write_file(f, fmt("%s%s", info$fin, separator));
    write_file(f, fmt("%s%s", info$rst, separator));
    write_file(f, fmt("%s%s", info$len, separator));
    write_file(f, fmt("%s%s", info$first, separator));
    write_file(f, fmt("%s%s", info$last, separator));
    if ( info$len == 0 )
        write_file(f, fmt("%s\n", empty_field));
    else
        write_file(f, fmt("%s\n", bytestring_to_hexstr(info$payload)));
    close(f);
}

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string) {
    local flag_orig: bool = contents_orig && is_orig;
    local flag_resp: bool = contents_resp && !is_orig;

    if ( flag_orig || flag_resp ) {
        local syn: bool = "S" in flags;
        local fin: bool = "F" in flags;
        local rst: bool = "R" in flags;

        if ( syn || fin || rst || ( len > 0 ) ) {
            local info: Info = [$filename=make_name(c, is_orig),
                                $ack=ack,
                                $seq=seq,
                                $syn=syn,
                                $fin=fin,
                                $rst=rst,
                                $len=len,
                                $first=seq,
                                $last=seq+len,
                                $payload=payload];
            use_json ? write_json(info) : write_text(info);
        }
    }
}
