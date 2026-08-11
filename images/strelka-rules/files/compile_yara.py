#!/usr/bin/env python3
"""把目录下所有 .yar 规则编译为单个 rules.compiled（与 SO compile_yara 行为对齐）

用法: compile_yara.py <rules_dir> <output_dir>
输出: <output_dir>/rules.compiled
"""

import glob
import os
import sys

import yara


def main():
    if len(sys.argv) != 3:
        sys.exit("用法: compile_yara.py <rules_dir> <output_dir>")
    rules_dir, out_dir = sys.argv[1], sys.argv[2]
    rule_files = sorted(glob.glob(os.path.join(rules_dir, "**", "*.yar"), recursive=True))
    if not rule_files:
        sys.exit(f"目录 {rules_dir} 下没有 .yar 规则")

    valid, failed = [], []
    seen = set()
    for f in rule_files:
        try:
            yara.compile(filepath=f)
            # 以文件名做命名空间（与 SO compile_yara 一致），避免跨文件重名规则冲突
            ns = os.path.basename(f)
            if ns in seen:
                print(f"[WARN] 重复文件名 {ns}，跳过 {f}", file=sys.stderr)
                continue
            seen.add(ns)
            valid.append(f)
        except yara.SyntaxError as exc:
            failed.append((f, str(exc)))
    for f, err in failed:
        print(f"[WARN] 规则语法错误 {f}: {err}", file=sys.stderr)

    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "rules.compiled")
    if valid:
        yara.compile(filepaths={os.path.basename(f): f for f in valid}).save(out)
        print(f"编译完成：{len(valid)}/{len(rule_files)} 条规则 -> {out}")
    if not valid:
        sys.exit("没有可用的规则，编译失败")


if __name__ == "__main__":
    main()
