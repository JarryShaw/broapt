##! Sumstats script to detect when many individuals receive the 
##! same document type file.

module Phishing;

@load base/frameworks/notice
@load base/frameworks/sumstats

export {
	redef enum Notice::Type += {
		## Indicates that a suspicious email document was seen
		Suspicious_Email_Document
	};

	## Time period to run analysis on emails
	global analysis_interval: interval = 15min &redef;
	## Maximum acceptable document attachment attachment_recipients
	global max_attachment_recipients: double = 5.0 &redef;
	## The file mime_types to keep track of
	global exploit_types: set[string] = {
		"application/java-archive",
		"application/x-java-applet",
		"application/x-java-jnlp-file",
		"application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/pdf",
		"application/x-dosexec",
		"application/zip"
	};
	## Provides the ability to whitelist emails that should not be monitored for attachments / phishing
	global Phishing::attachment_policy: hook(f: fa_file);
}

event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="phishing.attachment_recipients",
									$apply=set(SumStats::SUM)];
	SumStats::create([$name="phishing.email_docs",
					$epoch=analysis_interval,
			 		$reducers=set(r1),
			 		$threshold=max_attachment_recipients,
					$threshold_val(key: SumStats::Key, result: SumStats::Result) = 
						{
						return result["phishing.attachment_recipients"]$sum;
						},
					$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
						{
						local message = fmt("SHA1 %s seen with more than %g recipients", key$str, result["phishing.attachment_recipients"]$sum);
						local subtext = "Indicates mass mail of document files.";
						local i = Notice::Info($ts=network_time(),
											$note=Suspicious_Email_Document,
											$identifier=key$str,
											$msg=message,
											$sub=subtext);
						NOTICE(i);
						}]);
	}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( f?$source && f$source == "SMTP" )
		Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}

event file_state_remove(f: fa_file)
	{

	if ( ! f?$source || f$source != "SMTP")
		return;

	if ( f$info?$mime_type && f$info$mime_type in exploit_types && hook Phishing::attachment_policy(f) )
		{
		SumStats::observe("phishing.attachment_recipients",
							SumStats::Key($str=f$info$sha1),
							SumStats::Observation($num=1));
		}
	}