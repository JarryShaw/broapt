@load ../__load__.bro
@load base/protocols/irc/files.bro

module FileExtraction;

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=15 {
    if ( f$source == "IRC_DATA" )
        break;
}
