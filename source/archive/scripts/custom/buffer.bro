# buffer (from PyPCAPKit, c.f. pcapkit.reassembly.tcp.TCP_Reassembly._buffer)

type hole_t: record {
    first: count;
    last: count;
};

type part_t: record {
    isn:    count;
    len:    count;
    raw:    string;
};

type hdl_t: vector of hole_t;
type buf_t: table[count] of part_t;

type frag_t: record {
    hdl: hdl_t;
    buf: buf_t;
};

type buffer: table[string] of frag_t;

function comp_hdl(a: hole_t, b: hole_t): int {
    return ( a$first > b$first ) ? 1 : -1;
}s

function hdl_delete(HDL: hdl_t, idx: int): hdl_t {
    local range: int = 0;
    local new: hdl_t = vector();
    for ( h in HDL ) {
        if ( range != idx )
            new += HDL[h];
        ++ range;
    }
    return new;
}
