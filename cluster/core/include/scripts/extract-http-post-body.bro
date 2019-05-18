@load base/protocols/http/main

module HTTP;

redef record Info += {
	## HTTP entity data of POST method.
	post_body: string &optional &log &default="";
};

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( c$http?$method && c$http$method == "POST" )
		c$http$post_body += data;
	}
