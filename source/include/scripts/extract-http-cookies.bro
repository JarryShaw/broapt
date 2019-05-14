##! from policy/protocols/http/var-extraction-uri.bro

@load base/protocols/http/main

module HTTP;

redef record Info += {
	## All cookies.
	cookies: string &optional &log;
};

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( is_orig && name == "COOKIE" )
		c$http$cookies = value;
	}
