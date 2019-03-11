# bytearray (from Python, c.f. builtins.bytearray)

type bytearray: vector of string;

function bytearray_new(len: count, element: string &default=""): bytearray {
    local range: count = 0;
    local array: bytearray;
    while ( range < len ) {
        array += element;
        ++ range;
    }
    return array;
}

function string_to_bytearray(s: string): bytearray {
    local array: bytearray;
    for ( byte in s )
        array += byte;
    return array;
}

function bytearray_extend(base: bytearray, iterable: bytearray, start: count &default=0) {
    local index: count = start;
    local range: count;
    while ( range < |iterable| ) {
        base[index] = iterable[range];
        ++ index;
        ++ range;
    }
}

function bytearray_indice(base: bytearray, start: count &default=0): bytearray {
    local array: bytearray;
    local range: count = 0;
    while ( range < |base| ) {
        array += base[range];
        ++ range;
    }
    return array;
}
