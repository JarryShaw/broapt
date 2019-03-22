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

type buffer: table[conn_id] of frag_t;

function string_new(len: count, char: string &default="\x00"): string {
    local vec: vector of string;
    resize(vec, len+1);
    return cat_sep(vec, char);
}

function hdl_insert(base: hdl_t, index: count, new: hole_t) {
    if ( index >= |base| )
        base[|base|] = new;
    else {
        local range: count = index;
        while ( range < |base| ) {
            base[range+1] = base[range];
            ++ range;
        }
        base[index] = new;
    }
}

function hdl_delete(base: hdl_t, index: count): hdl_t {
    local new: hdl_t;
    local range: count = 0;
    while ( range < |base| ) {
        if ( range < index )
            new[range] = base[range];
        if ( range > index )
            new[range-1] = base[range];
        ++ range;
    }
    return new;
}
