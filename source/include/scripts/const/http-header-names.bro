module HTTP;

export {
    ## Message Headers from IANA
    ## https://www.iana.org/assignments/message-headers/message-headers.xml
    option header_names: set[string] = {
        "A-IM",
        "ACCEPT",
        "ACCEPT-ADDITIONS",
        "ACCEPT-CHARSET",
        "ACCEPT-DATETIME",
        "ACCEPT-ENCODING",
        "ACCEPT-FEATURES",
        "ACCEPT-LANGUAGE",
        "ACCEPT-PATCH",
        "ACCEPT-POST",
        "ACCEPT-RANGES",
        "ACCESS-CONTROL",
        "ACCESS-CONTROL-ALLOW-CREDENTIALS",
        "ACCESS-CONTROL-ALLOW-HEADERS",
        "ACCESS-CONTROL-ALLOW-METHODS",
        "ACCESS-CONTROL-ALLOW-ORIGIN",
        "ACCESS-CONTROL-MAX-AGE",
        "ACCESS-CONTROL-REQUEST-HEADERS",
        "ACCESS-CONTROL-REQUEST-METHOD",
        "AGE",
        "ALLOW",
        "ALPN",
        "ALT-SVC",
        "ALT-USED",
        "ALTERNATES",
        "AMP-CACHE-TRANSFORM",
        "APPLY-TO-REDIRECT-REF",
        "AUTHENTICATION-CONTROL",
        "AUTHENTICATION-INFO",
        "AUTHORIZATION",
        "C-EXT",
        "C-MAN",
        "C-OPT",
        "C-PEP",
        "C-PEP-INFO",
        "CACHE-CONTROL",
        "CAL-MANAGED-ID",
        "CALDAV-TIMEZONES",
        "CDN-LOOP",
        "CLOSE",
        "COMPLIANCE",
        "CONNECTION",
        "CONTENT-BASE",
        "CONTENT-DISPOSITION",
        "CONTENT-ENCODING",
        "CONTENT-ID",
        "CONTENT-LANGUAGE",
        "CONTENT-LENGTH",
        "CONTENT-LOCATION",
        "CONTENT-MD5",
        "CONTENT-RANGE",
        "CONTENT-SCRIPT-TYPE",
        "CONTENT-STYLE-TYPE",
        "CONTENT-TRANSFER-ENCODING",
        "CONTENT-TYPE",
        "CONTENT-VERSION",
        "COOKIE",
        "COOKIE2",
        "COST",
        "DASL",
        "DATE",
        "DAV",
        "DEFAULT-STYLE",
        "DELTA-BASE",
        "DEPTH",
        "DERIVED-FROM",
        "DESTINATION",
        "DIFFERENTIAL-ID",
        "DIGEST",
        "EARLY-DATA",
        "EDIINT-FEATURES",
        "ETAG",
        "EXPECT",
        "EXPECT-CT",
        "EXPIRES",
        "EXT",
        "FORWARDED",
        "FROM",
        "GETPROFILE",
        "HOBAREG",
        "HOST",
        "HTTP2-SETTINGS",
        "IF",
        "IF-MATCH",
        "IF-MODIFIED-SINCE",
        "IF-NONE-MATCH",
        "IF-RANGE",
        "IF-SCHEDULE-TAG-MATCH",
        "IF-UNMODIFIED-SINCE",
        "IM",
        "INCLUDE-REFERRED-TOKEN-BINDING-ID",
        "KEEP-ALIVE",
        "LABEL",
        "LAST-MODIFIED",
        "LINK",
        "LOCATION",
        "LOCK-TOKEN",
        "MAN",
        "MAX-FORWARDS",
        "MEMENTO-DATETIME",
        "MESSAGE-ID",
        "METER",
        "METHOD-CHECK",
        "METHOD-CHECK-EXPIRES",
        "MIME-VERSION",
        "NEGOTIATE",
        "NON-COMPLIANCE",
        "OPT",
        "OPTIONAL",
        "OPTIONAL-WWW-AUTHENTICATE",
        "ORDERING-TYPE",
        "ORIGIN",
        "OSCORE",
        "OVERWRITE",
        "P3P",
        "PEP",
        "PEP-INFO",
        "PICS-LABEL",
        "POSITION",
        "PRAGMA",
        "PREFER",
        "PREFERENCE-APPLIED",
        "PROFILEOBJECT",
        "PROTOCOL",
        "PROTOCOL-INFO",
        "PROTOCOL-QUERY",
        "PROTOCOL-REQUEST",
        "PROXY-AUTHENTICATE",
        "PROXY-AUTHENTICATION-INFO",
        "PROXY-AUTHORIZATION",
        "PROXY-FEATURES",
        "PROXY-INSTRUCTION",
        "PUBLIC",
        "PUBLIC-KEY-PINS",
        "PUBLIC-KEY-PINS-REPORT-ONLY",
        "RANGE",
        "REDIRECT-REF",
        "REFERER",
        "REFERER-ROOT",
        "REPLAY-NONCE",
        "RESOLUTION-HINT",
        "RESOLVER-LOCATION",
        "RETRY-AFTER",
        "SAFE",
        "SCHEDULE-REPLY",
        "SCHEDULE-TAG",
        "SEC-TOKEN-BINDING",
        "SEC-WEBSOCKET-ACCEPT",
        "SEC-WEBSOCKET-EXTENSIONS",
        "SEC-WEBSOCKET-KEY",
        "SEC-WEBSOCKET-PROTOCOL",
        "SEC-WEBSOCKET-VERSION",
        "SECURITY-SCHEME",
        "SERVER",
        "SET-COOKIE",
        "SET-COOKIE2",
        "SETPROFILE",
        "SLUG",
        "SOAPACTION",
        "STATUS-URI",
        "STRICT-TRANSPORT-SECURITY",
        "SUBOK",
        "SUBST",
        "SUNSET",
        "SURROGATE-CAPABILITY",
        "SURROGATE-CONTROL",
        "TCN",
        "TE",
        "TIMEOUT",
        "TIMING-ALLOW-ORIGIN",
        "TITLE",
        "TOPIC",
        "TRACEPARENT",
        "TRACESTATE",
        "TRAILER",
        "TRANSFER-ENCODING",
        "TTL",
        "UA-COLOR",
        "UA-MEDIA",
        "UA-PIXELS",
        "UA-RESOLUTION",
        "UA-WINDOWPIXELS",
        "UPGRADE",
        "URGENCY",
        "URI",
        "USER-AGENT",
        "VARIANT-VARY",
        "VARY",
        "VERSION",
        "VIA",
        "WANT-DIGEST",
        "WARNING",
        "WWW-AUTHENTICATE",
        "X-CONTENT-TYPE-OPTIONS",
        "X-DEVICE-ACCEPT",
        "X-DEVICE-ACCEPT-CHARSET",
        "X-DEVICE-ACCEPT-ENCODING",
        "X-DEVICE-ACCEPT-LANGUAGE",
        "X-DEVICE-USER-AGENT",
        "X-FRAME-OPTIONS",
    };
}
