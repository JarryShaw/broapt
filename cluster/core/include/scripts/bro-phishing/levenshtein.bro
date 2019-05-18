##! Phishing detection utilizing levenshtein algorithm to find 
##! senders using domains too close to locally used domain names

module Phishing;

@load base/frameworks/notice

export {
	redef enum Notice::Type += {
		## Raised when an SMTP mailfrom is too close to a domain defined within
		## the :bro:id:`Site::local_zones` variable.
		SMTP_Mail_From_too_Close,
		## Raised when an SMTP from is too close to a domain defined within
		## the :bro:id:`Site::local_zones` variable.
		SMTP_From_too_Close,
		## Raised when the SMTP reply_to is too close to a domain defined
		## within the :bro:id`Site::local_zones` variable.
		SMTP_Reply_To_too_Close
	};
	
	## Used to define the maximum difference in names that will raise a Notice.
	global max_distance: int = 4 &redef;
}

function parse_domain(s: string): string
	{
	local a = split_string(s, /@/);
	if ( |a| > 1 )
		{
		local b = split_string(a[1], />/);
		return b[0];
		}
	return "";
	}

event SMTP::log_smtp(rec: SMTP::Info)
	{
	if ( ! hook Phishing::policy(rec) )
		return;
	local domain = "";
	local msg: string;
	for ( zone in Site::local_zones )
		{
		if ( rec?$mailfrom )
			{
			domain = parse_domain(rec$mailfrom);
			if ( levenshtein_distance(domain, zone) < max_distance )
				{
				msg = fmt("local zone %s was too close to observed mailfrom %s",
							zone, rec$mailfrom);
				NOTICE([$note=SMTP_Mail_From_too_Close,
						$id=rec$id,
						$uid=rec$uid,
						$msg=msg]);
				}
			}
		if ( rec?$from )
			{
			domain = parse_domain(rec$from);
			if ( levenshtein_distance(domain, zone) < max_distance )
				{
				msg = fmt("local zone %s was too close to observed from %s",
						zone, rec$from);
				NOTICE([$note=SMTP_From_too_Close,
						$id=rec$id,
						$uid=rec$uid,
						$msg=msg]);
				}
			}
		if ( rec?$reply_to )
			{
			domain = parse_domain(rec$reply_to);
			if ( levenshtein_distance(domain, zone) < max_distance )
				{
				msg = fmt("local zone %s was too close to observed reply_to %s",
						zone, rec$reply_to);
				NOTICE([$note=SMTP_Reply_To_too_Close,
						$id=rec$id,
						$uid=rec$uid,
						$msg=msg]);
				}
			}
		}
	}