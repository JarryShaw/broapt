@load base/files/extract
@load base/frameworks/files
@load base/utils/files
# @load base/protocols/conn
@load misc/dump-events

redef LogAscii::use_json = T;
# redef Conn::default_extract = T;
# redef Conn::extraction_prefix = "";
redef FileExtract::default_limit=0;
redef Files::reassembly_buffer_size=0xffffffffffffffff;

redef tcp_content_deliver_all_orig=T;
redef tcp_content_deliver_all_resp=T;

# global default_extract = T;
global extraction_prefix = "";
global t: table[conn_id] of count;

# redef record connection += {
# 	extract_orig: bool &default=default_extract;
# 	extract_resp: bool &default=default_extract;
# };

function get_count(key: conn_id): count {
    if ( key in t ) {
        t[key] += 1;
    } else {
        t[key] = 0;
    }
    return t[key];
}

# event new_connection(c: connection) {
# 	print c$id;
# }

# event new_connection(c: connection) &priority=10 {
# 	if ( get_conn_transport_proto(c$id) != tcp )
# 		return;

# 	# print c$id;

# 	local orig_file = generate_extraction_filename(extraction_prefix, c, fmt("orig.%s.dat", get_count(c$id)));
# 	local orig_f = open(fmt("contents/%s", orig_file));
# 	set_contents_file(c$id, CONTENTS_ORIG, orig_f);
# 	# print fmt("contents/%s", orig_file);

# 	local resp_file = generate_extraction_filename(extraction_prefix, c, fmt("resp.%s.dat", get_count(c$id)));
# 	local resp_f = open(fmt("contents/%s", resp_file));
# 	set_contents_file(c$id, CONTENTS_RESP, resp_f);
# 	# print fmt("contents/%s", orig_file);
# }

# event file_sniff(f: fa_file, meta: fa_metadata) {
# 	print f$source, meta$mime_type;
# }

# event new_connection_contents(c: connection) {
# 	print c$id;
# }

# event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
# 	print flags;
# }

redef enum Log::ID += { REASS };

type Info: record {
	ts: 		time        &log;
	id: 		conn_id 	&log;
	seq:		count		&log;
	contents: 	string 		&log;
};

event bro_init() &priority=5 {
    Log::create_stream(REASS, [$columns=Info, $path="reass"]);
}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string) {
	# print c$id, contents;
	# print contents;
	# print "------";

	local id: conn_id;
	if ( is_orig )
		id = c$id;
	else
		id = [$orig_h=c$id$resp_h, $orig_p=c$id$resp_p,
			  $resp_h=c$id$orig_h, $resp_p=c$id$orig_p];
	print id;

	local rec: Info = [$ts=network_time(),
					   $id=id,
					   $seq=seq,
					   $contents=contents];
	Log::write(REASS, rec);
}

# event new_connection_contents(c: connection) {
# 	print c$id;

# 	local orig_file = generate_extraction_filename(extraction_prefix, c, fmt("orig.%s.dat", get_count(c$id)));
# 	local orig_f = open(fmt("contents/%s", orig_file));
# 	set_contents_file(c$id, CONTENTS_ORIG, orig_f);
# 	# print fmt("contents/%s", orig_file);

# 	local resp_file = generate_extraction_filename(extraction_prefix, c, fmt("resp.%s.dat", get_count(c$id)));
# 	local resp_f = open(fmt("contents/%s", resp_file));
# 	set_contents_file(c$id, CONTENTS_RESP, resp_f);
# 	# print fmt("contents/%s", orig_file);
# }
