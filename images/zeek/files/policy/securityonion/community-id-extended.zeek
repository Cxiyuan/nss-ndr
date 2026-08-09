##! NSS-NDR：把连接级 Community ID 扩展到 Files 与 SSL 日志，便于跨引擎/跨日志关联

module NSSNDR;

@load base/protocols/ssl
@load policy/protocols/conn/community-id-logging

export {
    redef record SSL::Info += {
        community_id: string &log &optional;
    };

    redef record Files::Info += {
        community_id: string &log &optional;
    };
}

event file_new(f: fa_file)
    {
    if ( ! f?$conns )
        return;
    for ( cid in f$conns )
        {
        local c = f$conns[cid];
        if ( c?$conn && c$conn?$community_id )
            {
            f$info$community_id = c$conn$community_id;
            break;
            }
        }
    }

event ssl_established(c: connection)
    {
    if ( c?$conn && c$conn?$community_id && c?$ssl )
        c$ssl$community_id = c$conn$community_id;
    }
