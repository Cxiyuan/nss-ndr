##! NSS-NDR：为连接记录注入探针标识（observer.name），支持多探针溯源

module NSSNDR;

export {
    ## 探针标识（由环境变量 NSS_SENSORNAME 注入）
    # const 不可运行时赋值，用 global 以便 zeek_init 注入环境变量
    global sensorname = "" &redef;

    redef record Conn::Info += {
        sensorname: string &log &optional;
    };
}

event connection_state_remove(c: connection)
    {
    if ( ! c?$conn )
        return;
    c$conn$sensorname = NSSNDR::sensorname;
    }

event zeek_init()
    {
    # 由环境变量 NSS_SENSORNAME 注入，缺省用主机名
    if ( getenv("NSS_SENSORNAME") != "" )
        NSSNDR::sensorname = getenv("NSS_SENSORNAME");
    else
        NSSNDR::sensorname = getenv("HOSTNAME");
    }
