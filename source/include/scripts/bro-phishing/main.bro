##! Phishing module for bro

module Phishing;

export {
	## Used to determine whether this script will analyze SMTP connections
	global policy: hook(rec: SMTP::Info);
}