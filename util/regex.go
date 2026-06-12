package util

import (
	"regexp"
	"sync"
)

var regexCache sync.Map

// CompileRegex 使用缓存来编译正则表达式，提高性能
func CompileRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}
