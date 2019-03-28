@load ../writer
@load base/utils/files

module Reass;

export {
    redef enum Log::ID += { LOG_FTP };

    type log_t: record {
        pkt:        pkt_t   &log;
        is_resp:    bool    &log &optional;
        command:    string  &log &optional;
        arg:        string  &log &optional;
        data_addr:  addr    &log &optional;
        data_port:  port    &log &optional;
        code:       count   &log &optional;
        msg:        string  &log &optional;
        cont_resp   bool    &log &optional;
    };

    # Define a logging event. By convention, this is called
    # "log_<stream>".
    global log_ftp: event(rec: log_t);
}

global ftp_conn: set[string];
global ftp_data: table[string] of set[conn_id];

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=20 {
    add ftp_conn[c$uid];
}

event ftp_request(c: connection, command: string, arg: string) &priority=20 {
    add ftp_conn[c$uid];

    local port_info: ftp_port;
    switch (to_upper(command)) {
        case "EPRT":
            port_info = parse_eftp_port(arg);
            break;
        case "EPSV":
            port_info = parse_ftp_epsv(arg);
            break;
        case "PASV":
            port_info = parse_ftp_pasv(arg);
            break;
        case "PORT":
            port_info = parse_ftp_port(arg);
            break;
        default:
            return;
    }

    if ( port_info$valid ) {
        if ( c$uid !in ftp_data )
            ftp_data[c$uid] = set();
        add ftp_data[c$uid][port_info];
    }
}

hook Reass::predicate(s: string, pkt: pkt_t) {
    if ( pkt$uid in ftp_conn )
        return;

    if ( pkt$uid in ftp_data ) {
        local port_info: ftp_port;

        port_info = [$h=pkt$id$orig_h, $p=pkt$id$orig_p, $valid=T];
        if ( port_info in ftp_data[pkt$uid] )
            return;

        port_info = [$h=pkt$id$resp_h, $p=pkt$id$resp_p, $valid=T];
        if ( port_info in ftp_data[pkt$uid] )
            return;
    }

    Log::write(LOG_FTP, rec);
}

event bro_init() &priority=5 {
    # Specify the "log_ftp" event here in order for Bro to raise it.
    Log::create_stream(Reass::LOG_FTP, [$columns=log_t, $ev=Reass::log_ftp, $path="reass_ftp"]);
}
