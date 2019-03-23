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

type hdl_t: set[hole_t];
type buf_t: table[count] of part_t;

type frag_t: record {
    hdl: hdl_t;
    buf: buf_t;
};

type buffer: table[string] of frag_t;

function comp_hdl(a: hole_t, b: hole_t): int {
    return ( a$first > b$first ) ? 1 : -1;
}

function sort_hdl(HDL: hdl_t): vector of hole_t {
    local vec: vector of hole_t;
    for ( hole in HDL )
        vec += hole;
    return sort(vec, comp_hdl);
}
