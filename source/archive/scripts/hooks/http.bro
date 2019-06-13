@load ../plugins/http

module Reass;

hook Reass::predicate(s: string, pkt: pkt_t) {
    if ( !is_http(s, pkt) )
        break;
}
