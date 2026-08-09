##! NSS-NDR：从 /opt/zeek/etc/bpf 动态加载 BPF 过滤（可热重载）

module NSSNDR;

@load base/frameworks/notice

export {
    const bpf_conf_file = "/opt/zeek/etc/bpf" &redef;

    redef enum Notice::Type += {
        InvalidBPF
    };
}

global filter_parts: vector of string = vector();
global current_file = "";

redef enum PcapFilterID += {
    NSSNDR_BPF
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
    {
    local part = sub(s, /[[:blank:]]*#.*$/, "");
    if ( part != "" )
        filter_parts[|filter_parts|] = part;
    }

event Input::end_of_data(name: string, source: string)
    {
    if ( name != "nssndr-bpf" )
        return;
    local filter = join_string_vec(filter_parts, " ");
    filter_parts = vector();
    if ( filter == "" )
        return;

    if ( Pcap::precompile_pcap_filter(NSSNDR_BPF, filter) )
        {
        capture_filters["bpf.conf"] = filter;
        PacketFilter::install();
        }
    else
        NOTICE([$note=InvalidBPF,
                $msg=fmt("Compiling BPF from %s failed: %s", bpf_conf_file, filter),
                $sub=filter]);
    }

event zeek_init() &priority=5
    {
    if ( bpf_conf_file == "" )
        return;
    if ( bpf_conf_file != current_file )
        {
        current_file = bpf_conf_file;
        Input::add_event([$source=bpf_conf_file,
                          $name="nssndr-bpf",
                          $reader=Input::READER_RAW,
                          $mode=Input::REREAD,
                          $want_record=F,
                          $fields=record { s: string; },
                          $ev=line]);
        }
    }
