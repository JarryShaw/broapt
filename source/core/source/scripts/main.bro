@load base/files/extract
@load base/frameworks/files

@load base/utils/paths.bro
@load ./file-extensions.bro

module FileExtraction;

export {
    ## If store files by MIME types
    option mime: bool = T;
    ## Path to missing MIME log file
    option logs: string = "/var/log/bro/processed_mime.log";

    ## Log format
    const use_json: bool = LogAscii::use_json &redef;
    ## Change hash salt
    const file_salt: string = Files::salt &redef;
    ## Buffer size for file reassembly
    const file_buffer: count = Files::reassembly_buffer_size &redef;

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
    }
}
