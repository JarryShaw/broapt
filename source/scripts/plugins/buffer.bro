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

type hdl_t: vector of hole_t;
type buf_t: table[count] of part_t;

type frag_t: record {
    hdl: hdl_t;
    buf: buf_t;
};

type buffer: table[string] of frag_t;

function vector_insert(base: hdl_t, index: count, new_hole: hole_t) {
    local range: count = index;
    while ( range < |base| ) {
        base[range+1] = base[range];
        ++ range;
    }
    base[index] = new_hole;
}

function vector_delete(base: hdl_t, index: count): hdl_t {
    local range: count = index+1;
    local new: hdl_t = copy(base);
    while ( range < |base| ) {
        new[range-1] = base[range];
        ++ range;
    }
    return new;
}
