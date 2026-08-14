##! NSS-NDR：把连接级 Community ID 扩展到全部协议日志
##! 使 DNS/HTTP/QUIC/X509/SSH/DHCP/SOCKS/SSL/Files/SMB/NTLM 等日志都带 community_id，
##! 便于跨引擎（Suricata/Zeek）与跨日志类型关联。

module NSSNDR;

@load base/protocols/ssl
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/quic
@load base/protocols/ssh
@load base/protocols/dhcp
@load base/protocols/socks
@load base/files/x509
@load base/protocols/smb
@load base/protocols/ntlm
@load policy/protocols/conn/community-id-logging

export {
    redef record SSL::Info += {
        community_id: string &log &optional;
    };
    redef record Files::Info += {
        community_id: string &log &optional;
    };
    redef record DNS::Info += {
        community_id: string &log &optional;
    };
    redef record HTTP::Info += {
        community_id: string &log &optional;
    };
    redef record QUIC::Info += {
        community_id: string &log &optional;
    };
    redef record X509::Info += {
        community_id: string &log &optional;
    };
    redef record SSH::Info += {
        community_id: string &log &optional;
    };
    redef record DHCP::Info += {
        community_id: string &log &optional;
    };
    redef record SOCKS::Info += {
        community_id: string &log &optional;
    };
    redef record SMB::FileInfo += {
        community_id: string &log &optional;
    };
    redef record SMB::TreeInfo += {
        community_id: string &log &optional;
    };
    redef record NTLM::Info += {
        community_id: string &log &optional;
    };

    ## conn_id -> community_id 映射（写入事件时连接上下文不可直接访问，用映射表兜底）
    global cid_map: table[conn_id] of string = table();
}

# 取连接级 community_id（由 community-id-logging 在 new_connection 时写入 c$conn）
function get_cid(c: connection): string
    {
    if ( c?$conn && c$conn?$community_id )
        return c$conn$community_id;
    return "";
    }

event file_new(f: fa_file)
    {
    if ( ! f?$conns )
        return;
    for ( cid in f$conns )
        {
        local c = f$conns[cid];
        local id = get_cid(c);
        if ( id != "" )
            {
            f$info$community_id = id;
            break;
            }
        }
    }

event ssl_established(c: connection)
    {
    if ( c?$ssl )
        {
        local id = get_cid(c);
        if ( id != "" )
            c$ssl$community_id = id;
        }
    }

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=5
    {
    if ( c?$dns )
        {
        local id = get_cid(c);
        if ( id != "" )
            c$dns$community_id = id;
        }
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( c?$http )
        {
        local id = get_cid(c);
        if ( id != "" )
            c$http$community_id = id;
        }
    }

event QUIC::initial_packet(c: connection, is_orig: bool, version: count,
                           dcid: string, scid: string)
    {
    if ( c?$quic )
        {
        local id = get_cid(c);
        if ( id != "" )
            c$quic$community_id = id;
        }
    }

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
    {
    if ( ! f?$info || ! f?$conns )
        return;
    if ( ! f$info?$x509 )
        return;
    for ( cid in f$conns )
        {
        local c = f$conns[cid];
        local id = get_cid(c);
        if ( id != "" )
            {
            f$info$x509$community_id = id;
            break;
            }
        }
    }

event ssh_auth_attempted(c: connection, authenticated: bool) &priority=5
    {
    if ( c?$ssh )
        {
        local id = get_cid(c);
        if ( id != "" )
            c$ssh$community_id = id;
        }
    }

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg,
                   options: DHCP::Options) &priority=5
    {
    if ( c?$dhcp )
        {
        local id = get_cid(c);
        if ( id != "" )
            c$dhcp$community_id = id;
        }
    }

event socks_request(c: connection, version: count, request_type: count,
                    sa: SOCKS::Address, p: port, user: string)
    {
    if ( c?$socks )
        {
        local id = get_cid(c);
        if ( id != "" )
            c$socks$community_id = id;
        }
    }

function fill_from_conn_id(id: conn_id): string
    {
    if ( id in cid_map )
        return cid_map[id];
    return "";
    }

event new_connection(c: connection)
    {
    if ( c?$conn && c$conn?$community_id )
        cid_map[c$id] = c$conn$community_id;
    }

event connection_state_remove(c: connection)
    {
    delete cid_map[c$id];
    }

## SMB 文件访问 / 共享映射 / NTLM 认证日志在写出前注入连接级 Community ID
hook SMB::log_policy_files(rec: any, id: Log::ID, filter: Log::Filter)
    {
    local fi = rec as SMB::FileInfo;
    if ( fi?$id )
        fi$community_id = fill_from_conn_id(fi$id);
    }

hook SMB::log_policy_mapping(rec: any, id: Log::ID, filter: Log::Filter)
    {
    local ti = rec as SMB::TreeInfo;
    if ( ti?$id )
        ti$community_id = fill_from_conn_id(ti$id);
    }

hook NTLM::log_policy(rec: any, id: Log::ID, filter: Log::Filter)
    {
    local ni = rec as NTLM::Info;
    if ( ni?$id )
        ni$community_id = fill_from_conn_id(ni$id);
    }
