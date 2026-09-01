#!/usr/bin/env python3
# 创建 saltapi 系统用户(替代 Alpine 不存在的 adduser/chpasswd)
import crypt, os
user = "saltapi"
pw = "saltapi-pass"
pw_hash = crypt.crypt(pw, crypt.mksalt())
lines = open('/etc/passwd').read().splitlines()
if not any(l.startswith(user+':') for l in lines):
    with open('/etc/passwd','a') as f:
        f.write(f'{user}:x:10003:10003:saltapi:/home/saltapi:/sbin/nologin\n')
    with open('/etc/group','a') as f:
        f.write('saltapi:x:10003:\n')
try:
    shadow = open('/etc/shadow').read().splitlines()
except FileNotFoundError:
    shadow = []
shadow = [l for l in shadow if not l.startswith(user+':')]
shadow.append(f'{user}:{pw_hash}:18000:0:99999:7:::')
with open('/etc/shadow','w') as f:
    f.write('\n'.join(shadow)+'\n')
os.chmod('/etc/shadow', 0o640)
os.makedirs('/home/saltapi', mode=0o755, exist_ok=True)
print(f"[create-saltapi] created user {user} (uid 10003)")
