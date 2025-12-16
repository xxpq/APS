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
// 支持两种认证方式：
// 1. 用户名:密码 - 标准的 Basic 认证
// 2. x-access-token:token - 使用 token 进行认证
func (p *MapRemoteProxy) checkAuth(r *http.Request, mapping *Mapping) (bool, *User, string) {
	serverConfig := p.config.Servers[p.serverName]
	if serverConfig == nil {
		return true, nil, "" // 理论上不应发生
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
		return true, nil, ""
	}

	// 如果配置了 auth 块但没有指定任何用户或组，则拒绝所有请求
	if len(requiredUsers) == 0 && len(requiredGroups) == 0 {
		return false, nil, ""
	}

	// 解析 Proxy-Authorization header
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false, nil, ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false, nil, ""
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, nil, ""
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return false, nil, ""
	}
	username, password := creds[0], creds[1]

	// 验证用户是否存在
	if p.config.Auth == nil || p.config.Auth.Users == nil {
		return false, nil, ""
	}

	// 检查是否是 x-access-token 认证方式
	if username == "x-access-token" {
		// 使用 token 进行认证
		for uname, u := range p.config.Auth.Users {
			if u.Token != "" && u.Token == password {
				// Token 匹配成功
				user := u
				username = uname

				// 检查用户是否在允许的用户列表中
				for _, requiredUser := range requiredUsers {
					if username == requiredUser {
						return true, user, username
					}
				}

				// 检查用户是否属于任何一个允许的组
				for _, requiredGroup := range requiredGroups {
					for _, userGroup := range user.Groups {
						if userGroup == requiredGroup {
							return true, user, username
						}
					}
				}

				// Token 正确但不满足权限要求
				return false, nil, ""
			}
		}
		// Token 不匹配
		return false, nil, ""
	}

	// 标准的用户名:密码认证
	user, ok := p.config.Auth.Users[username]
	if !ok || user.Password != password {
		return false, nil, ""
	}

	// 检查用户是否在允许的用户列表中
	for _, requiredUser := range requiredUsers {
		if username == requiredUser {
			return true, user, username
		}
	}

	// 检查用户是否属于任何一个允许的组
	for _, requiredGroup := range requiredGroups {
		for _, userGroup := range user.Groups {
			if userGroup == requiredGroup {
				return true, user, username
			}
		}
	}

	// 如果用户凭据正确，但不满足当前规则的权限要求，则拒绝
	return false, nil, ""
}

// checkTunnelAccess 检查已认证的用户是否有权访问特定的隧道
func (p *MapRemoteProxy) checkTunnelAccess(user *User, username string, tunnelAuth *RuleAuth) bool {
	// 如果隧道没有配置认证，则允许所有用户访问
	if tunnelAuth == nil || (len(tunnelAuth.Users) == 0 && len(tunnelAuth.Groups) == 0) {
		return true
	}

	// 如果隧道需要认证，但当前请求是匿名的，则拒绝
	if user == nil {
		return false
	}

	// 检查用户是否在允许的用户列表中
	for _, requiredUser := range tunnelAuth.Users {
		if username == requiredUser {
			return true
		}
	}

	// 检查用户是否属于任何一个允许的组
	for _, requiredGroup := range tunnelAuth.Groups {
		for _, userGroup := range user.Groups {
			if userGroup == requiredGroup {
				return true
			}
		}
	}

	return false
}

// checkProxyPermission 检查用户是否有代理使用权限
// 返回值: (hasPermission bool, errorMessage string)
func (p *MapRemoteProxy) checkProxyPermission(user *User, username string) (bool, string) {
	// 如果用户为 nil（匿名访问），则无权限
	if user == nil {
		return false, "Proxy access requires authentication"
	}

	// 检查用户是否直接配置了 proxy 权限
	if user.Proxy {
		return true, ""
	}

	// 检查用户所属的组是否有 proxy 权限
	if p.config.Auth != nil && p.config.Auth.Groups != nil {
		for _, groupName := range user.Groups {
			if group, ok := p.config.Auth.Groups[groupName]; ok {
				// 注意：Group 结构体中没有 Proxy 字段，所以这里只检查用户级别
				// 如果需要组级别的 proxy 权限，需要在 Group 结构体中添加 Proxy 字段
				_ = group // 避免未使用的变量警告
			}
		}
	}

	// 用户没有代理权限
	return false, "User does not have proxy permission"
}
