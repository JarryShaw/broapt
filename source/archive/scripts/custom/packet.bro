# packet (from PyPCAPKit, c.f. pcapkit.reassembly.tcp.datagram[...])

type pkt_t: record {
    id:     conn_id &log;
    uid:    string  &log;
    ack:    count   &log;
    len:    count   &log;
    start:  count   &log &optional;
    stop:   count   &log &optional;
};
