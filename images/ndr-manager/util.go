package main

import "time"

func nowStr() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// configMapHash 简单返回当前时间戳作为"已下发"标识（后续可改为内容 hash）
func configMapHash() string {
	return nowStr()
}
