# 配置指南 - 双向 Headers 和 Match/Replace

## 概述

本代理工具现在支持对 `from` 和 `to` 进行高级配置，允许您：

1. **请求端（from）**：设置自定义请求头、匹配和替换请求数据
2. **响应端（to）**：设置自定义响应头、匹配和替换响应数据
3. **跨域头优先级**：自定义 headers 优先级高于默认跨域 headers

## 配置格式

### 1. 简单字符串格式（向后兼容）

```json
{
  "from": "https://api.openai.com/v1*",
  "to": "https://backend.example.com/v1*"
}
```

### 2. 对象格式（新功能）

```json
{
  "from": {
    "url": "https://api.openai.com/v1*",
    "headers": {
      "Authorization": "Bearer your-token",
      "X-Custom-Header": "custom-value"
    }
  },
  "to": {
    "url": "https://backend.example.com/v1*",
    "headers": {
      "Access-Control-Allow-Origin": "https://specific-domain.com",
      "X-Response-Header": "response-value"
    },
    "match": "<title>(.*?)</title>",
    "replace": {
      "OldBrand": "NewBrand"
    }
  }
}
```

## EndpointConfig 结构

```json
{
  "url": "string (required)",
  "headers": {
    "Header-Name": "header-value"
  },
  "match": "regex-pattern",
  "replace": {
    "search-pattern": "replacement"
  }
}
```

### 字段说明

- **url**: 目标 URL（必需）
- **headers**: 要设置的 HTTP 头（可选）
- **match**: 正则表达式，用于提取响应体中的内容（可选）
- **replace**: 键值对，用于替换响应体中的内容（可选）

## 功能详解

### 1. 请求体匹配和替换（from.match & from.replace）

**新增功能**：现在 `from` 配置也支持 `match` 和 `replace`，用于处理请求体。

```json
{
  "from": {
    "url": "https://api.example.com/*",
    "headers": {
      "Content-Type": "application/json"
    },
    "match": "\"request\":\\s*\\{([^}]+)\\}",
    "replace": {
      "\"oldField\"": "\"newField\"",
      "sensitive-key": "***"
    }
  },
  "to": "https://backend.example.com/*"
}
```

**效果**：
- `from.match`：从请求体中提取匹配的内容
- `from.replace`：替换请求体中的内容
- 处理后的请求体会发送到目标服务器

### 2. 请求头设置（from.headers）

在 `from` 配置中设置的 headers 会应用到发出的代理请求上：

```json
{
  "from": {
    "url": "https://api.example.com/*",
    "headers": {
      "Authorization": "Bearer secret-token",
      "X-API-Key": "your-api-key",
      "User-Agent": "MyProxy/1.0"
    }
  },
  "to": "https://backend.example.com/*"
}
```

**效果**：所有匹配 `from.url` 的请求都会附加这些请求头。

### 3. 响应头设置（to.headers）

在 `to` 配置中设置的 headers 会应用到返回给客户端的响应上：

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "headers": {
      "Access-Control-Allow-Origin": "https://trusted-site.com",
      "Cache-Control": "max-age=3600",
      "X-Powered-By": "MyProxy"
    }
  }
}
```

**重要**：`to.headers` 中设置的响应头会**覆盖**默认的跨域头。

### 4. 响应体匹配（to.match）

使用正则表达式提取响应体中的特定内容：

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "match": "<title>(.*?)</title>"
  }
}
```

**效果**：只返回匹配到的第一个捕获组的内容。如果没有匹配，返回空响应。

### 5. 响应体替换（to.replace）

使用正则表达式替换响应体中的内容：

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "replace": {
      "OldBrand": "NewBrand",
      "example\\.com": "myproxy.com",
      "\"status\":\"success\"": "\"status\":\"modified\""
    }
  }
}
```

**效果**：按顺序应用所有替换规则。

### 6. 正则表达式 URL 匹配（from.url）

**新增功能**：`from.url` 现在支持正则表达式匹配。

```json
{
  "from": "https://api\\.example\\.com/v(\\d+)/users/(\\d+)",
  "to": "https://backend.example.com/api/v$1/user/$2"
}
```

**效果**：
- 请求 `https://api.example.com/v2/users/123` 会被映射到 `https://backend.example.com/api/v2/user/123`
- 使用 `$1`, `$2` 等引用捕获组

**正则表达式检测规则**：
- 如果 URL 包含 `(`, `[`, `{`, `^`, `$`, `|` 等正则特征字符，会尝试作为正则表达式处理
- 如果不是有效的正则表达式，会回退到原始的字符串匹配逻辑
- 简单的 `*` 通配符仍然按照原来的方式处理

**更多示例**：

```json
{
  "comment": "匹配特定路径模式",
  "from": "https://old-api\\.example\\.com/(v\\d+)/(.*)",
  "to": "https://new-api.example.com/$1/$2"
}
```

```json
{
  "comment": "使用对象配置 + 正则表达式",
  "from": {
    "url": "https://api\\.example\\.com/(.+)/data",
    "headers": {
      "X-Source": "proxy"
    }
  },
  "to": "https://backend.example.com/api/$1/info"
}
```

### 7. 双向配置示例

同时配置请求和响应的完整示例：

```json
{
  "from": {
    "url": "https://api.example.com/v1*",
    "headers": {
      "Authorization": "Bearer request-token",
      "X-Request-ID": "custom-id"
    }
  },
  "to": {
    "url": "https://backend.example.com/api/v1*",
    "headers": {
      "Access-Control-Allow-Origin": "*",
      "X-Response-Time": "100ms"
    },
    "match": "\"data\":\\s*\\{([^}]+)\\}",
    "replace": {
      "sensitive": "***",
      "internal": "external"
    }
  }
}
```

## 跨域头处理

### 默认跨域头

代理工具默认会设置以下跨域头：

```
Origin: *
Timing-Allow-Origin: *
Access-Control-Allow-Origin: *
Vary: Etag, Save-Data, Accept-Encoding
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: *
Access-Control-Request-Method: *
Access-Control-Request-Headers: *
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: cross-origin
```

### OPTIONS 请求处理

所有 OPTIONS 请求会自动返回 200 状态码，并应用上述默认跨域头。

### 自定义跨域头优先级

**重要**：在 `to.headers` 中设置的响应头会**覆盖**默认跨域头。

例如，如果您想限制特定域的访问：

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "headers": {
      "Access-Control-Allow-Origin": "https://trusted-site.com",
      "Access-Control-Allow-Credentials": "true"
    }
  }
}
```

这会将 `Access-Control-Allow-Origin` 从默认的 `*` 改为 `https://trusted-site.com`。

## 向后兼容性

旧的配置格式仍然完全支持：

```json
{
  "from": "https://api.example.com/*",
  "to": "https://backend.example.com/*",
  "headers": {
    "Authorization": "Bearer token"
  },
  "match": "<title>(.*?)</title>",
  "replace": {
    "old": "new"
  }
}
```

这种配置会被自动转换为：
- `headers` → `from.headers`（请求头）
- `match` → `to.match`（响应匹配）
- `replace` → `to.replace`（响应替换）

## 实际应用场景

### 场景 1：API 密钥注入

```json
{
  "from": {
    "url": "https://public-api.example.com/*",
    "headers": {
      "X-API-Key": "secret-key-12345"
    }
  },
  "to": "https://backend-api.example.com/*"
}
```

### 场景 2：响应数据脱敏

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "replace": {
      "\"password\":\"[^\"]+\"": "\"password\":\"***\"",
      "\"credit_card\":\"[^\"]+\"": "\"credit_card\":\"****\""
    }
  }
}
```

### 场景 3：品牌替换

```json
{
  "from": "https://white-label.example.com/*",
  "to": {
    "url": "https://original-service.com/*",
    "replace": {
      "Original Brand": "Your Brand",
      "original-logo.png": "your-logo.png"
    }
  }
}
```

### 场景 4：CORS 精细控制

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "headers": {
      "Access-Control-Allow-Origin": "https://app.yourdomain.com",
      "Access-Control-Allow-Methods": "GET, POST",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400"
    }
  }
}
```

## 日志输出

代理工具会记录详细的日志信息：

- `[REQUEST HEADERS]`：应用请求头时
- `[RESPONSE HEADERS]`：应用响应头时
- `[RESPONSE MATCH]`：匹配响应内容时
- `[RESPONSE REPLACE]`：替换响应内容时

示例日志：

```
[REQUEST HEADERS] Applying 3 custom headers from 'from' config
[REQUEST HEADERS]   Authorization: Bearer ***
[REQUEST HEADERS]   X-API-Key: ***
[REQUEST HEADERS]   User-Agent: MyProxy/1.0
[RESPONSE HEADERS] Applying 2 custom headers from 'to' config
[RESPONSE HEADERS]   Access-Control-Allow-Origin: https://trusted-site.com
[RESPONSE HEADERS]   Cache-Control: max-age=3600
[RESPONSE MATCH] Extracted 1024 bytes from response body
[RESPONSE REPLACE] Applied replacement: OldBrand -> NewBrand
```

## 注意事项

1. **正则表达式性能**：复杂的正则表达式可能影响性能，请谨慎使用
2. **Headers 优先级**：`to.headers` 会覆盖默认跨域头和源站响应头
3. **Match 行为**：如果 `match` 没有匹配到内容，会返回空响应
4. **Replace 顺序**：替换按照配置中的顺序依次应用
5. **向后兼容**：旧配置格式会自动转换，无需修改现有配置

## 完整示例

参考 `config.example.json` 文件查看更多完整示例。