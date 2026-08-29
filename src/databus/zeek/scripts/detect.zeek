## 通用行为检测脚本（占位 · 根据实际网络补充规则）
@load base/protocols/conn

event connection_state_remove(c: connection)
  {
  if ( c?$conn && c$conn?$orig_bytes && c$conn$orig_bytes > 100000000 )
    {
    print(fmt("Large outbound transfer detected: %d bytes from %s",
              c$conn$orig_bytes, c$id$orig_h));
    }
  }
