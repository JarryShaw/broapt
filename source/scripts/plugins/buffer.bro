@load ./bytearray.bro

# buffer (from PyPCAPKit, c.f. pcapkit.reassembly.tcp.TCP_Reassembly._buffer)

type hole_t: record {
    first: count;
    last: count;
};

type part_t: record {
    isn:    count;
    len:    count;
    raw:    bytearray;
};

type hdl_t: table[count] of hole_t;
type buf_t: table[count] of part_t;

type frag_t: record {
    hdl: hdl_t;
    buf: buf_t;
};

type buffer: table[string] of frag_t;

function table_insert(base: hdl_t, index: count, new: hole_t) {
    local range: count = index;
    while ( range < |base| ) {
        base[range+1] = base[range];
        ++ range;
    }
    base[index] = new;
}

function table_delete(base: hdl_t, index: count) {
    local range: count = index;
    while ( range < |base|-1 ) {
        base[range] = base[range+1];
        ++ range;
    }
    delete base[|base|-1];
}
