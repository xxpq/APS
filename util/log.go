// Package util 提供项目全局共享的辅助函数。
//
// DebugLog / IsDebugMode：debug 日志输出控制。
// 历史背景：这两个符号原本定义在根目录 config.go 中（package main），
// 由于被 30+ 个文件调用，拆包时直接在原位置改 re-export 会更平滑。
// 本文件是 Stage 0 预硬化的产物，Stage 1 会把其他 util 类文件（utils.go、pools.go 等）搬进来。
package util

import "log"

// IsDebugMode 全局 debug 模式标志。
// 启动时由 main.go 从 CLI flag 赋值，DebugLog 据此决定是否输出。
var IsDebugMode bool = false

// DebugLog 只在 debug 模式下输出日志。
// 调用方应使用 fmt 风格 format + args（与 log.Printf 一致）。
func DebugLog(format string, args ...interface{}) {
	if IsDebugMode {
		log.Printf(format, args...)
	}
}
