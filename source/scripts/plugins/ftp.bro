@load ../writer
@load ../vendor/files

module Reass;

export {
    redef enum Log::ID += { LOG_FTP };

    type log_t: record {
        pkt:        pkt_t   &log;
        is_data:    bool    &log;
        is_resp:    bool    &log &optional;
        command:    string  &log &optional;
        arg:        string  &log &optional;
        data_addr:  addr    &log &optional;
        data_port:  port    &log &optional;
        code:       count   &log &optional;
        msg:        string  &log &optional;
        cont_resp:  bool    &log &optional;
    };

    # Define a logging event. By convention, this is called
    # "log_<stream>".
    global log_ftp: event(rec: log_t);
}

global ftp_data: table[string] of set[conn_id];

function parse_port(command: string, arg: string): ftp_port {
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
    }
    return port_info;
}

function is_ftp(s: string, pkt: pkt_t): bool {
    local rec: log_t;
    local text: string;
    if ( pkt$uid in ftp_data && pkt$id in ftp_data[pkt$uid] )
        rec = [$pkt=pkt,
               $is_data=T];
    else {
        if ( s[-2:] != "\r\n" )
            return F;
        text = s[:-2];
        if ( |split_string1(text, /\n/)| != 1 )
            return F;

        if ( /^[0-9][0-9][0-9]/ in text ) {
            local msg: string;
            local cont_resp: bool;

            local code: count = to_count(text[:3]);
            if ( |text| > 3 ) {
                cont_resp = ( text[3] == "-" ) ? T : F;
                msg = text[4:];
            }

            rec = [$pkt=pkt,
                   $is_data=F,
                   $is_resp=T,
                   $code=code,
                   $msg=msg,
                   $cont_resp=cont_resp];
        } else {
            local command: string;
            local arg: string = "";

            local vec: string_vec = split_string1(text, /( )+/);
            if ( |vec| == 2 ) {
                command = vec[0];
                arg = vec[1];
            } else
                command = vec[0];

            rec = [$pkt=pkt,
                   $is_data=F,
                   $is_resp=F,
                   $command=command,
                   $arg=arg];

            if ( command == /EPRT|EPSV|PASV|PORT/i ) {
                local port_info: ftp_port = parse_port(command, arg);
                if ( port_info$valid ) {
                    rec$data_addr = port_info$h;
                    rec$data_port = port_info$p;

                    local data_conn: conn_id = [$orig_h=port_info$h,
                                                $orig_p=port_info$p,
                                                $resp_h=pkt$id$resp_h,
                                                $resp_p=pkt$id$resp_p];
                    if ( pkt$uid !in ftp_data )
                        ftp_data[pkt$uid] = set();
                    add ftp_data[pkt$uid][data_conn];
                }
            }
        }
    }

    Log::write(LOG_FTP, rec);
    return T;
}

hook Reass::predicate(s: string, pkt: pkt_t) {
    if ( !is_ftp(s, pkt) )
        break;
}

event connection_state_remove(c: connection) {
    delete ftp_data[c$uid];
}

event bro_init() &priority=5 {
    # Specify the "log_ftp" event here in order for Bro to raise it.
    Log::create_stream(Reass::LOG_FTP, [$columns=log_t, $ev=Reass::log_ftp, $path="reass_ftp"]);
}
