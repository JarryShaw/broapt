@load base/protocols/http/main

module HTTP;

type header_rec: record {
	name: string &log;
	value: string &log;
};

redef record Info += {
	## All headers.
	headers: set[header_rec] &optional &log;
};

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=2 
	{
	local headers: set[header_rec];
	local mime_header: header_rec;
	for ( cnt in hlist )
		{
		mime_header = hlist[cnt];
		headers += [$name=mime_header$name,
					$value=mime_header$value]
		}
		c$http$headers = headers;
	}
