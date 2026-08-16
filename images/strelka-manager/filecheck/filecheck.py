#!/usr/bin/env python3
"""NSS-NDR Strelka filecheck

参照 Security Onion 3.1.0 的实现（filecheck）：
  - 监听 Zeek 提取目录 /nsm/zeek/extracted/complete
  - 对每个文件算 SHA1：history 中有记录说明已扫描过 -> 删除文件；
    否则写入 history 标记并移动到 /nsm/strelka/unprocessed 交给 filestream
  - watchdog 观察器每 recycle_secs 重建一次（SO 做法，用于拾取新子目录）
  - 周期清理 history 中超过 history_clean_days 的记录（SO 用 cron 实现，此处内嵌）
"""

import hashlib
import logging
import os
import shutil
import threading
import time

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

with open("/opt/so/conf/strelka/filecheck.yaml", "r") as f:
    cfg = yaml.safe_load(f)["filecheck"]

extract_path = cfg["extract_path"]
historypath = cfg["historypath"]
strelkapath = cfg["strelkapath"]
logfile = cfg["logfile"]
history_clean_days = int(cfg.get("history_clean_days", 2))
recycle_secs = int(cfg.get("recycle_secs", 300))
history_clean_interval = int(cfg.get("history_clean_interval", 3600))

logging.basicConfig(
    filename=logfile,
    filemode="a",
    format="%(asctime)s - %(message)s",
    datefmt="%d-%b-%y %H:%M:%S",
    level=logging.INFO,
)


def sha1_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            buf = f.read(8192)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def process(filename):
    if not os.path.isfile(filename):
        return
    digest = sha1_file(filename)
    marker = os.path.join(historypath, digest)
    if os.path.exists(marker):
        logging.info("%s 已扫描过，删除", filename)
        os.remove(filename)
        return
    logging.info("%s 新文件，入队 Strelka", filename)
    with open(marker, "w") as f:
        f.write("")
    shutil.move(filename, os.path.join(strelkapath, os.path.basename(filename)))


def checkexisting():
    logging.info("扫描已有文件")
    for root, _dirs, files in os.walk(extract_path):
        for name in files:
            try:
                process(os.path.join(root, name))
            except Exception as exc:  # noqa: BLE001
                logging.error("处理失败 %s: %s", name, exc)


class CreatedEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            process(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            process(event.dest_path)


def history_cleaner():
    cutoff = time.time() - history_clean_days * 86400
    try:
        for name in os.listdir(historypath):
            p = os.path.join(historypath, name)
            try:
                if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
                    os.remove(p)
            except OSError:
                pass
        logging.info("history 清理完成（>%d 天）", history_clean_days)
    except Exception as exc:  # noqa: BLE001
        logging.error("history 清理失败: %s", exc)


def start_history_cleaner():
    while True:
        time.sleep(history_clean_interval)
        history_cleaner()


if __name__ == "__main__":
    logging.info("filecheck 启动（extract=%s）", extract_path)
    threading.Thread(target=start_history_cleaner, daemon=True).start()
    while True:
        checkexisting()
        observer = Observer()
        observer.schedule(CreatedEventHandler(), extract_path, recursive=True)
        observer.start()
        try:
            time.sleep(recycle_secs)
        except KeyboardInterrupt:
            observer.stop()
            break
        observer.stop()
        observer.join()
        logging.info("重建观察器（拾取新子目录）")
