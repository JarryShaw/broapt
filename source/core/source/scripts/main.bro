@load base/utils/paths
@load ./file-extensions

module FileExtraction;

export {
    ## If store files by MIME types
    const mime: bool = T &redef;
    ## Path to store files
    const path: string = FileExtract::prefix &redef;

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
                if ( mime )
                    fext = "dat";
                else
                    fext = cat(sub(mgct, /\//, "."), ".dat");
                system(fmt("echo '%s' >> /pcap/processed_mime.log", mgct));
            }
        } else {
            mgct = "application/octet-stream";
            fext = "dat";
        }

        if ( mime ) {
            local root = split_string(mgct, /\//)[0];
            mkdir(fmt("%s/%s", path, root));
            mkdir(fmt("%s/%s", path, mgct));
        } else
            mgct = ".";

        local name = fmt("%s/%s-%s.%s", mgct, f$source, f$id, fext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=name]);
    }
}
