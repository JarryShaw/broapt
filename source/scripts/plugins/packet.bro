@load ./bytearray.bro

# packet (from PyPCAPKit, c.f. pcapkit.reassembly.tcp.datagram[...])

type pkt_t: record {
    conn:   conn_id;
    ack:    count;
    id:     string;
    payload: string;
};

function bytearray_to_string(base: bytearray): string {
    # print fmt("bytearray_to_string(%s)", |base|);
    local s: string = "";
    for ( index in base )
        s += base[index];
    return s;
}
