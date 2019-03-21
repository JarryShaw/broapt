@load base/utils/patterns.bro

global HTTP_REQUEST: set[string] = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE"
] &redef;
global HTTP_RESPONSE: set[string] = ["HTTP"] &redef;

function is_http(s: string): bool {
    local http: pattern = set_to_regex(HTTP_REQUEST + HTTP_RESPONSE, "|");
    return match_pattern(s, http)$matched;
}
