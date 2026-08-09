##! NSS-NDR：按 MIME 白名单提取网络文件到 /nsm/zeek/extracted/complete/
##! 文件需完整（md5 存在、字节数非 0、未超时），否则删除临时文件

module NSSNDR;

@load base/frameworks/files
# Zeek 8 中 exec 框架位于 base/utils/exec（base/frameworks/exec 不存在）
@load base/utils/exec

export {
    redef FileExtract::prefix = "/nsm/zeek/extracted/";
    redef FileExtract::default_limit = 9000000;

    ## MIME 白名单：mime -> 扩展名
    const file_extraction_mimes: table[string] of string = {
        ["application/x-dosexec"] = "exe",
        ["application/pdf"] = "pdf",
        ["application/msword"] = "doc",
        ["application/vnd.ms-excel"] = "xls",
        ["application/rtf"] = "rtf",
        ["application/zip"] = "zip",
        ["application/x-7z-compressed"] = "7z",
        ["application/x-rar-compressed"] = "rar",
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
        ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx"
    } &redef;
}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=10
    {
    if ( ! meta?$mime_type )
        return;
    if ( meta$mime_type !in file_extraction_mimes )
        return;

    local fname = fmt("%s-%s.%s", f$source, f$id, file_extraction_mimes[meta$mime_type]);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }

event file_state_remove(f: fa_file)
    {
    if ( ! f$info?$extracted || FileExtract::prefix == "" )
        return;

    # 不完整/超时/零字节 直接丢弃
    if ( ! f$info?$md5 ||
         (f?$total_bytes && f$total_bytes == 0) ||
         f$missing_bytes > 0 ||
         f$info$timedout )
        {
        local nuke = fmt("rm -f %s/%s", FileExtract::prefix, f$info$extracted);
        when [nuke] ( local r = Exec::run([$cmd=nuke]) ) { }
        return;
        }

    local orig = f$info$extracted;
    local parts = split_string(orig, /\./);
    local ext = parts[|parts|-1];
    local dest = fmt("%scomplete/%s-%s-%s.%s",
                     FileExtract::prefix, f$source, f$id, f$info$md5, ext);
    local move = fmt("cp %s/%s %s && rm -f %s/%s",
                     FileExtract::prefix, orig, dest, FileExtract::prefix, orig);
    when [move] ( local mv = Exec::run([$cmd=move]) ) { }
    f$info$extracted = dest;
    }
