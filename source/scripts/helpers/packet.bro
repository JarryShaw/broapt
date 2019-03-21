@load ./bytearray.bro

# packet (from PyPCAPKit, c.f. pcapkit.reassembly.tcp.datagram[...])

type pkt_t: record {
    id:     conn_id &log;
    uid:    string  &log;
    ack:    count   &log;
    len:    count   &log;
    start:  count   &log &optional;
    stop:   count   &log &optional;
};

function bytearray_to_string(base: bytearray): string {
    # print fmt("bytearray_to_string(%s)", |base|);
    return join_string_vec(base, "");
    # local s: string = "";
    # local index: count = 0;
    # while ( index < |base| ) {
    #     s += base[index];
    #     ++ index;
    # }
    # return s;
}
