package main

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// checkAuth 检查请求是否满足认证要求
// 优先级: mapping auth > server auth
// 如果 mapping 和 server 都没有 auth 配置，则允许访问
// 如果任一级别配置了 auth，但请求没有提供有效的凭据，则拒绝访问
func (p *MapRemoteProxy) checkAuth(r *http.Request, mapping *Mapping) (bool, *User) {
	serverConfig := p.config.Servers[p.serverName]
	if serverConfig == nil {
		return true, nil // 理论上不应发生
	}

	// 确定当前生效的认证规则
	var requiredUsers, requiredGroups []string
	authConfigured := false

	if mapping != nil && mapping.Auth != nil {
		requiredUsers = mapping.Auth.Users
		requiredGroups = mapping.Auth.Groups
		authConfigured = true
	} else if serverConfig.Auth != nil {
		requiredUsers = serverConfig.Auth.Users
		requiredGroups = serverConfig.Auth.Groups
		authConfigured = true
	}

	// 如果没有配置认证规则，则直接通过
	if !authConfigured {
		return true, nil
	}

	// 如果配置了 auth 块但没有指定任何用户或组，则拒绝所有请求
	if len(requiredUsers) == 0 && len(requiredGroups) == 0 {
		return false, nil
	}

	// 解析 Proxy-Authorization header
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false, nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, nil
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return false, nil
	}
	username, password := creds[0], creds[1]

	// 验证用户是否存在且密码正确
	if p.config.Auth == nil || p.config.Auth.Users == nil {
		return false, nil
	}
	user, ok := p.config.Auth.Users[username]
	if !ok || user.Password != password {
		return false, nil
	}

	// 检查用户是否在允许的用户列表中
	for _, requiredUser := range requiredUsers {
		if username == requiredUser {
			return true, user
		}
	}

	// 检查用户是否属于任何一个允许的组
	for _, requiredGroup := range requiredGroups {
		for _, userGroup := range user.Groups {
			if userGroup == requiredGroup {
				return true, user
			}
		}
	}

	// 如果用户凭据正确，但不满足当前规则的权限要求，则拒绝
	return false, nil
}