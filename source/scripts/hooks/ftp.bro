@load ../plugins/ftp

module Reass;

hook Reass::predicate(s: string, pkt: pkt_t) {
    if ( !is_ftp(s, pkt) )
        break;
}
