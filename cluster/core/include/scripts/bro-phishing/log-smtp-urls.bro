##! Create a log containing all links seen in emails

module Phishing;

@load base/protocols/smtp
@load base/utils/urls

export {
	## Create log stream
	redef enum Log::ID += { Links_LOG };

	type Info: record {
		## Timestamp pulled from the SMTP record
		ts:		time &log;
		## Connection UID to tie the log to the conn log
		uid:	string &log;
		## SMTP MAILFROM header
		from:	string &log &optional;
		## SMTP RCPTTO header
		to: 	set[string] &log &optional;
		## The host portion of the URL found
		host: 	string &log;
		## The path of the URL found
		path:	string	&log;
	};

	## Event fired when a link is found in an email
	global link_found: event(host: string, path: string);
}

event bro_init()
	{
	Log::create_stream(Phishing::Links_LOG, [$columns=Info]);
	}

event mime_all_data(c: connection, length: count, data: string)
	{
	if ( ! c?$smtp )
		return;

	# Get all of the URLs from the mime data
	local urls = find_all_urls_without_scheme(data);
	# Loop through each of the links, logging them
	for ( url in urls )
		{

		# Basic parsing of URL to make the log more useful
		local uri = split_string1(url, /\//);
		local host = uri[0];
		local path = "";
		if ( |uri| > 1 )
			{
			path = "/" + uri[1];
			}

		# Fire an event for additional use of this information
		event Phishing::link_found(host, path);

		local i: Info;

		i$ts = c$smtp$ts;
		i$uid = c$smtp$uid;
		if ( c$smtp?$mailfrom )
			i$from = c$smtp$mailfrom;
		if ( c$smtp?$rcptto )
			i$to = c$smtp$rcptto;
		i$host = host;
		i$path = path;

		# Log the link to the links log
		Log::write(Links_LOG, i);
		}
	}