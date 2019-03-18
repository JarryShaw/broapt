# bytearray (from Python, c.f. builtins.bytearray)

type bytearray: vector of string;

function bytearray_new(len: count, element: string &default=""): bytearray {
    # print fmt("bytearray_new(len: %s, element: %s)", len, element);
    local range: count = 0;
    local array: bytearray;
    while ( range < len ) {
        array[range] = element;
        ++ range;
    }
    return array;
}

function string_to_bytearray(s: string): bytearray {
    # print fmt("string_to_bytearray(%s)", |s|);
    local index: count = 0;
    local array: bytearray;
    for ( byte in s ) {
        array[index] = byte;
        ++ index;
    }
    return array;
}

function bytearray_extend(base: bytearray, iter: bytearray, start: count &default=0xffffffffffffffff) {
    # print fmt("bytearray_extend(base: %s, iter: %s, start: %s)", |base|, |iter|, start);
    local index: count = ( start >= |base| ) ? |base| : start;
    for ( range in iter ) {
        base[index] = iter[range];
        ++ index;
    }
}

function bytearray_indice(base: bytearray, start: count &default=0, end: count &default=0xffffffffffffffff): bytearray {
    # print fmt("bytearray_indice(base: %s, start: %s)", |base|, start);
    local stop: count = ( end >= |base| ) ? |base| : end;
    local index: count = start;

    local array: bytearray;
    local range: count = 0;
    while ( index < stop ) {
        array[range] = base[index];
        ++ index;
        ++ range;
    }
    return array;
}
