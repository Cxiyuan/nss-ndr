"""Redis Lua 脚本：水位 + 结论原子写回（设计文档 §3、§13.5）。"""

# KEYS[1] = agent:result:{sess} 结果键
# ARGV[1] = verdict JSON（含 watermark 字段）
# ARGV[2] = TTL 秒
# 返回值 = 旧值（便于审计与对比）
WRITE_VERDICT_LUA = """
local old = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return old or ''
"""

# KEYS[1] = evt:{event_id}（幂等去重标记）
# 返回 1=首次看到（需处理），0=已处理过
SEEN_EVENT_LUA = """
return redis.call('SET', KEYS[1], 1, 'EX', ARGV[1], 'NX') and 1 or 0
"""

# KEYS[1] = lock:{sess}
# ARGV[1] = 持有者 token，ARGV[2] = TTL 秒
# 返回 1=拿到锁，0=拿不到（被占用）
ACQUIRE_LOCK_LUA = """
return redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX') and 1 or 0
"""

# KEYS[1] = lock:{sess}，ARGV[1] = 持有者 token
# 只有 token 匹配才释放（防误删他人锁）
RELEASE_LOCK_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"""
