@load ../main
@load base/utils/patterns

module Reass;

global HTTP_METHOD: pattern = /GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE/i &redef;
global HTTP_VERSION: pattern = /HTTP\/[0-9]\.[0-9]/i &redef;
global HTTP_STATUS: pattern = /[0-9][0-9][0-9]/i &redef;

hook Reass::predicate(s: string): bool {
    local vec: string_vec;

    vec = split_string1(s, /\x0d\x0a\x0d\x0a/);
    if ( |vec| != 2 )
        break;

    local header: string = vec[0];
    local body: string = vec[1];

    vec = split_string1(header, /\x0d\x0a/);
    local startline: string = vec[0];

    vec = split_string_n(startline, /[ \t\n\r\f\v]+/, F, 2);
    if ( |vec| != 3 )
        break;
    local para1: string = vec[0];
    local para2: string = vec[1];
    local para3: string = vec[2];

    local match1: PatternMatchResult = match_pattern(para1, HTTP_METHOD);
    local match2: PatternMatchResult = match_pattern(para3, HTTP_VERSION);
    local match3: PatternMatchResult = match_pattern(para1, HTTP_VERSION);
    local match4: PatternMatchResult = match_pattern(para2, HTTP_STATUS);

    if ( !( match1$matched && match2$matched ) && !( match3$matched && match4$matched ) )
        break;
}
