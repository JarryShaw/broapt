@load base/protocols/http/main

module HTTP;

redef record Info += {
	## All headers.
	headers: string &optional &log;
};

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=2 {
    local headers: string = "";
    local mime_header: mime_header_rec;
    for ( cnt in hlist ) {
        mime_header = hlist[cnt];
        headers += fmt("%s: %s\r\n", mime_header$name, mime_header$value);
    }
    c$http$headers = headers;
}
