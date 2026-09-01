#!/usr/bin/env python3
# ============================================================================
# 修补 salt/utils/event.py 的 _fire_ret_load_specific_fun
# ----------------------------------------------------------------------------
# 问题: salt 3007.14 在 Python 3.10/3.12 下, 当 minion return 是 str/list 时
#       (cmd.run 返回 str, state.single 返回 list),
#       for tag, data in ret.items() 崩溃 (str/list 无 .items()),
#       事件丢失 → salt CLI 等不到 return 超时。
# 修复: ret 不是 dict 时不迭代, 直接发 job-ret 事件。
# 用法: 在 Dockerfile 中 RUN python3 /opt/patch-event.py
# ============================================================================

SRC = "/usr/local/lib/python3.10/site-packages/salt/utils/event.py"

with open(SRC) as f:
    content = f.read()

OLD = """        try:
            for tag, data in ret.items():
                data["retcode"] = retcode
                tags = tag.split("_|-")
                if data.get("result") is False:
                    self.fire_event(data, f"{tags[0]}.{tags[-1]}")  # old dup event
                    data["jid"] = load["jid"]
                    data["id"] = load["id"]
                    data["success"] = False
                    data["return"] = f"Error: {tags[0]}.{tags[-1]}"
                    data["fun"] = fun
                    if "user" in load:
                        data["user"] = load["user"]
                    self.fire_event(
                        data,
                        tagify([load["jid"], "sub", load["id"], "error", fun], "job"),
                    )
        except Exception as exc:  # pylint: disable=broad-except
            log.error(
                "Event iteration failed with exception: %s",
                exc,
                exc_info_on_loglevel=logging.DEBUG,
            )"""

NEW = """        if isinstance(ret, dict):
            try:
                for tag, data in ret.items():
                    if isinstance(data, dict):
                        data["retcode"] = retcode
                    tags = tag.split("_|-")
                    if isinstance(data, dict) and data.get("result") is False:
                        self.fire_event(data, f"{tags[0]}.{tags[-1]}")  # old dup event
                        data["jid"] = load["jid"]
                        data["id"] = load["id"]
                        data["success"] = False
                        data["return"] = f"Error: {tags[0]}.{tags[-1]}"
                        data["fun"] = fun
                        if "user" in load:
                            data["user"] = load["user"]
                        self.fire_event(
                            data,
                            tagify([load["jid"], "sub", load["id"], "error", fun], "job"),
                        )
            except Exception as exc:  # pylint: disable=broad-except
                log.error(
                    "Event iteration failed with exception: %s",
                    exc,
                    exc_info_on_loglevel=logging.DEBUG,
                )
        else:
            # Non-dict return (str/list): fire raw ret as job-ret so salt CLI sees it
            self.fire_event(
                {"return": ret, "retcode": retcode, "jid": load.get("jid", ""), "id": load.get("id", "")},
                tagify([load.get("jid", ""), "ret", load.get("id", "")], "job"),
            )"""

if OLD not in content:
    # 已打过 patch 则幂等退出
    print("OK: already patched or pattern not found (idempotent)")
else:
    content = content.replace(OLD, NEW)
    with open(SRC, "w") as f:
        f.write(content)
    print("OK: patched event.py")
