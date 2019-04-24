@load ../__load__.bro

module FileExtraction;

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5 {
    local mime_wl: string_vec = split_string(getenv("BRO_MIME"), /[[:space:]]*,[[:space:]]*/);
    if ( meta?$mime_type ) {
        local mime_type: string = meta$mime_type;
        for ( index in mime_wl )
            if ( mime_wl[index] == mime_type )
                break;
    }
}
