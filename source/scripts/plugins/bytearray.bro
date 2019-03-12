# bytearray (from Python, c.f. builtins.bytearray)

type bytearray: vector of string;

function bytearray_new(len: count, element: string &default=""): bytearray {
    # print fmt("bytearray_new(len: %s, element: %s)", len, element);
    local range: count = 0;
    local array: bytearray;
    while ( range < len ) {
        array += element;
        ++ range;
    }
    return array;
}

function string_to_bytearray(s: string): bytearray {
    # print fmt("string_to_bytearray(%s)", |s|);
    local array: bytearray;
    for ( byte in s )
        array += byte;
    return array;
}

function bytearray_extend(base: bytearray, iterable: bytearray, start: count &default=0) {
    # print fmt("bytearray_extend(base: %s, iterable: %s, start: %s)", |base|, |iterable|, start);
    local index: count = start;
    for ( range in iterable ) {
        base[index] = iterable[range];
        ++ index;
    }
}

function bytearray_indice(base: bytearray, start: count &default=0): bytearray {
    # print fmt("bytearray_indice(base: %s, start: %s)", |base|, start);
    local array: bytearray;
    local index: count = start;
    while ( index < |base| ) {
        array += base[index];
        ++ index;
    }
    return array;
}
