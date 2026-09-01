#!/usr/bin/env python3
# 修补 salt/utils/rsax931.py 的 _find_libcrypto
# Alpine musl 下 ctypes.util.find_library('crypto') 返回 None (无 ld.so.cache),
# 导致 salt-master 启动报 OSError: Cannot locate OpenSSL libcrypto
# 修复: find_library 失败时 fallback 到 /usr/lib/libcrypto.so.3 (Alpine 路径)

SRC = "/usr/local/lib/python3.10/site-packages/salt/utils/rsax931.py"

with open(SRC) as f:
    content = f.read()

OLD = """    else:
        lib = ctypes.util.find_library("crypto")
        if not lib:"""

NEW = """    else:
        lib = ctypes.util.find_library("crypto")
        if not lib:
            # Alpine/musl fallback: find_library 依赖 ld.so.cache (musl 无),
            # 直接找 /usr/lib/libcrypto.so*
            lib = glob.glob("/usr/lib/libcrypto.so*")
            lib = lib[0] if lib else None
            if not lib:
                lib = glob.glob("/lib/libcrypto.so*")
                lib = lib[0] if lib else None
        if not lib:"""

if OLD not in content:
    print("OK: already patched or pattern not found (idempotent)")
else:
    content = content.replace(OLD, NEW)
    with open(SRC, "w") as f:
        f.write(content)
    print("OK: patched rsax931.py")
