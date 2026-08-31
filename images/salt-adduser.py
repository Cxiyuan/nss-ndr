#!/usr/bin/env python3
# ============================================================================
# Salt 镜像初始化用户脚本（Alpine 3.21 BusyBox adduser 不可用兜底）
# ----------------------------------------------------------------------------
# 创建 salt 用户（uid 10002，无登录 shell，home=/home/salt，密码锁定）
# 并创建同名 salt 组（gid 10002）。
# Alpine 3.21 + python3 自带 crypt 模块，无需额外依赖。
# 用法（容器构建时）：COPY images/salt-adduser.py /tmp/salt-adduser.py
#                      RUN python3 /tmp/salt-adduser.py
# ============================================================================
import crypt
import os
import sys


def main() -> int:
    if os.path.exists("/home/salt"):
        # 幂等：已创建则跳过（CI 缓存复用场景）
        print("[salt-adduser] /home/salt already exists, skip")
        return 0

    # 密码字段：!locked 表示账号被锁定（无法用密码登录，但 uid 仍可用于 chown）
    pw = crypt.crypt("!locked", crypt.mksalt())
    user_line = f"salt:{pw}:10002:10002:salt:/home/salt:/sbin/nologin\n"
    group_line = "salt:x:10002:\n"

    with open("/etc/passwd", "a") as f:
        f.write(user_line)
    with open("/etc/group", "a") as f:
        f.write(group_line)

    os.makedirs("/home/salt", mode=0o755, exist_ok=True)
    print("[salt-adduser] created salt user (uid=10002, gid=10002, locked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())