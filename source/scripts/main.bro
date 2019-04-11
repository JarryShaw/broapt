@load base/utils/paths
@load ./file-extensions

module FileExtraction;

export {
    ## Path to store files
    const path: string = FileExtract::prefix &redef;
    ## Hook to include files in extraction
    global extract: hook(f: fa_file, meta: fa_metadata);
    ## Hook to exclude files from extraction
    global ignore: hook(f: fa_file, meta: fa_metadata);
}

@if ( path != FileExtract::prefix )
    redef FileExtract::prefix = path;
@endif

event file_sniff(f: fa_file, meta: fa_metadata) {
    if ( !hook FileExtraction::ignore(f, meta) )
        return;

    if ( !hook FileExtraction::extract(f, meta) ) {
        local fext: string;
        local mime: string;
        if ( meta?$mime_type ) {
            mime  = meta$mime_type;
            if ( mime in mime_to_ext )
                fext = mime_to_ext[mime];
            else
                fext = split_string(mime, /\//)[1];
        } else {
            mime = "application/octet-stream";
            fext = "dat";
        }

        local root = split_string(mime, /\//)[0];
        mkdir(fmt("%s/%s", path, root));
        mkdir(fmt("%s/%s", path, mime));

        local name = fmt("%s/%s-%s.%s", mime, f$source, f$id, fext);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=name]);
    }
}
