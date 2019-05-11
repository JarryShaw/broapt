@load base/files/extract
@load base/frameworks/files

@load base/files/hash
@load base/utils/paths.bro
@load ./file-extensions.bro

module FileExtraction;

export {
    ## Log format
    option use_json: bool = LogAscii::use_json;
    ## Change hash salt
    option file_salt: string = Files::salt;
    ## Buffer size for file reassembly
    option file_buffer: count = Files::reassembly_buffer_size;

    ## Include X509 information
    option x509: bool = F;
    ## Include entropy information
    option entropy: bool = F;

    ## Path to missing MIME log file
    const logs: string = "/var/log/bro/processed_mime.log" &redef;
    ## If store files by MIME types
    const mime: bool = T &redef;

    ## Calculate MD5 value of extracted files
    const md5: bool = F &redef;
    ## Calculate SHA1 value of extracted files
    const sha1: bool = F &redef;
    ## Calculate SHA256 value of extracted files
    const sha256: bool = F &redef;

    ## Path to store files
    const path_prefix: string = FileExtract::prefix &redef;
    ## Size limit for extracted files
    const size_limit: count = FileExtract::default_limit &redef;

    ## Hook to include files in extraction
    global extract: hook(f: fa_file, meta: fa_metadata);
    ## Hook to exclude files from extraction
    global ignore: hook(f: fa_file, meta: fa_metadata);
}

event file_sniff(f: fa_file, meta: fa_metadata) {
    if ( !hook FileExtraction::ignore(f, meta) )
        return;

    if ( !hook FileExtraction::extract(f, meta) ) {
        local fext: string;
        local mgct: string;

        if ( meta?$mime_type ) {
            mgct = meta$mime_type;
            if ( mgct in mime_to_ext )
                fext = mime_to_ext[mgct];
            else {
                fext = "dat";
                system(fmt("echo '%s' >> '%s'", mgct, logs));
            }
        } else {
            mgct = "application/octet-stream";
            fext = "dat";
        }

        if ( mime ) {
            local root = split_string(mgct, /\//)[0];
            mkdir(fmt("%s/%s", path_prefix, root));
            mkdir(fmt("%s/%s", path_prefix, mgct));
        } else {
            mgct = ".";
            fext = cat(sub(mgct, /\//, "."), ".", fext);
        }

        local name = fmt("%s/%s-%s.%s", mgct, f$source, f$id, fext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=name]);

        if ( md5 )
            Files::add_analyzer(f, Files::ANALYZER_MD5);
        if ( sha1 )
            Files::add_analyzer(f, Files::ANALYZER_SHA1);
        if ( sha256 )
            Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }
}
