@load base/utils/paths
@load ./file-extensions

module FileExtraction;

export {
    ## If store files by MIME types
    option mime: bool = T;
    ## Path to store files
    option path: string = FileExtract::prefix;
    ## Path to missing MIME log file
    option logs: string = "/var/log/bro/processed_mime.log";

    ## Buffer size for file reassembly
    option buffer_size: count = Files::reassembly_buffer_size;
    ## Size limit for extracted files
    option size_limit: count = FileExtract::default_limit;

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
            mkdir(fmt("%s/%s", path, root));
            mkdir(fmt("%s/%s", path, mgct));
        } else {
            mgct = ".";
            fext = cat(sub(mgct, /\//, "."), ".", fext);
        }

        local name = fmt("%s/%s-%s.%s", mgct, f$source, f$id, fext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=name]);
    }
}
