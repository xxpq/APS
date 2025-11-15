# Proxy Tool - 高级 HTTP/HTTPS 代理工具

一个功能强大的 HTTP/HTTPS 代理工具，支持 URL 重映射、请求/响应体修改、自定义头部、正则表达式匹配等高级功能。

## ✨ 核心特性

### 🔄 双向数据处理

- **请求处理**：修改请求头、匹配和替换请求体
- **响应处理**：修改响应头、匹配和替换响应体
- 支持正则表达式进行复杂的内容匹配和替换

### 🎯 灵活的 URL 映射

- 简单字符串匹配（支持 `*` 通配符）
- **正则表达式匹配**：支持捕获组和动态替换
- 本地文件服务
- 专用端口监听

### 🔐 安全与跨域

- 自动 HTTPS 证书生成
- 完整的 CORS 跨域支持
- OPTIONS 请求自动处理
- 可自定义跨域头（优先级高于默认配置）

### 📊 调试与监控

- 详细的请求/响应日志
- HAR 格式日志记录
- 配置热重载
- Carbon Copy（请求复制）功能

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone <repository-url>
cd proxy_tool

# 编译
go build -o proxy_tool.exe .
```

### 基本使用

1. 创建配置文件 `config.json`：

```json
{
  "mappings": [
    {
      "from": "https://api.example.com/*",
      "to": "https://backend.example.com/*"
    }
  ]
}
```

2. 启动代理：

```bash
./proxy_tool.exe
```

3. 配置浏览器或应用使用代理：
   - HTTP 代理：`127.0.0.1:8080`
   - HTTPS 代理：`127.0.0.1:8080`

## 📖 配置详解

### 配置文件结构

```json
{
  "server": {
    "port": 3000,
    "cert": "auto"
  },
  "mappings": [
    {
      "from": "string | object",
      "to": "string | object",
      "local": "string (optional)",
      "listen": "number | object (optional)",
      "cc": ["string array (optional)"]
    }
  ]
}
```

### ⚠️ Mapping 规则验证

代理工具在加载配置时会自动验证每条 mapping 规则，不符合要求的规则会被**自动过滤并跳过**。

#### 必需字段验证

1. **`from` 字段必须存在**

   - `from` 不能为 `null` 或缺失
   - `from.url` 不能为空字符串
   - 如果 `from` 解析失败，该规则会被跳过
2. **`to` 和 `local` 至少存在一个**

   - 必须配置 `to`（代理转发）或 `local`（本地文件）
   - 两者都不存在时，该规则会被跳过
   - 如果配置了 `to`，则 `to.url` 不能为空

#### 可选字段行为

- **`method` 字段**：
  - 不配置时：匹配**所有 HTTP 方法**（GET、POST、PUT、DELETE 等）
  - 配置后：只匹配指定的方法
  - 支持字符串或数组格式

#### 验证示例

**✅ 有效配置**：

```json
{
  "from": "https://api.example.com/*",
  "to": "https://backend.example.com/*"
}
```

**✅ 有效配置（本地文件）**：

```json
{
  "from": "/static/*",
  "local": "./public/*"
}
```

**✅ 有效配置（method 未配置，匹配所有方法）**：

```json
{
  "from": {
    "url": "https://api.example.com/*",
    "headers": {
      "Authorization": "Bearer token"
    }
  },
  "to": "https://backend.example.com/*"
}
```

**❌ 无效配置（缺少 from）**：

```json
{
  "to": "https://backend.example.com/*"
}
```

*错误日志*：`Warning: mapping 1 skipped - 'from' field is required`

**❌ 无效配置（to 和 local 都缺失）**：

```json
{
  "from": "https://api.example.com/*"
}
```

*错误日志*：`Warning: mapping 1 skipped - either 'to' or 'local' field is required`

**❌ 无效配置（from.url 为空）**：

```json
{
  "from": {
    "url": "",
    "headers": {"Authorization": "Bearer token"}
  },
  "to": "https://backend.example.com/*"
}
```

*错误日志*：`Warning: mapping 1 skipped - 'from' URL is empty`

#### 启动日志示例

```
Loaded 3 valid mapping rules (filtered from 5 total)
  [1] https://api.example.com/* -> https://backend.example.com/*
  [2] /static/* -> [LOCAL] ./public/*
  [3] https://secure-api.com/* -> https://secure-backend.com/* (with custom headers)
```

当配置文件中有 5 条规则但只有 3 条有效时，日志会显示 `(filtered from 5 total)`。

### Server 配置（公共服务器）

`server` 字段为**可选的顶层配置**，用于为相对路径的 mapping 提供统一的 HTTP/HTTPS 服务器。

#### 基本格式

```json
{
  "server": {
    "port": 3000,
    "cert": "auto"
  }
}
```

#### 字段说明

- `port`（必需）：公共服务器监听的端口
- `cert`（可选）：证书配置
  - `"auto"`：自动生成证书
  - 对象格式：指定证书文件路径
    ```json
    {
      "cert": {
        "cert": "./.cert/server.crt",
        "key": "./.cert/server.key"
      }
    }
    ```

#### 相对路径 Mapping 规则

当满足以下**所有条件**时，mapping 会自动分配给公共服务器：

1. `from.url` 以 `/` 开头（相对路径）
2. 没有配置 `listen` 字段（或 `listen.port` 为 0）
3. 配置文件中定义了 `server` 字段

**示例**：

```json
{
  "server": {
    "port": 3000,
    "cert": "auto"
  },
  "mappings": [
    {
      "comment": "使用公共服务器 - 本地文件服务",
      "from": "/static/*",
      "local": "./static/*"
    },
    {
      "comment": "使用公共服务器 - 代理转发到远程",
      "from": "/api/*",
      "to": "https://backend.example.com/api/*"
    },
    {
      "comment": "使用公共服务器 - 带 headers 的代理转发",
      "from": {
        "url": "/auth/*",
        "method": ["GET", "POST"],
        "headers": {
          "X-Custom-Header": "value"
        }
      },
      "to": {
        "url": "https://auth-service.com/*",
        "headers": {
          "Access-Control-Allow-Origin": "https://trusted.com"
        }
      }
    },
    {
      "comment": "使用独立端口（有 listen 配置）",
      "from": "/admin/*",
      "local": "./admin/*",
      "listen": 8081
    },
    {
      "comment": "普通代理规则（绝对 URL）",
      "from": "https://api.example.com/*",
      "to": "https://backend.example.com/*"
    }
  ]
}
```

**访问方式**：

- 公共服务器本地文件：`http://localhost:3000/static/file.js`
- 公共服务器代理转发：`http://localhost:3000/api/data` → `https://backend.example.com/api/data`
- 公共服务器带配置转发：`http://localhost:3000/auth/login` → `https://auth-service.com/login`
- 独立端口：`http://localhost:8081/admin/index.html`
- 普通代理：通过主代理端口（默认 8080）访问

#### 公共服务器支持的功能

公共服务器（相对路径 mapping）支持以下两种模式：

1. **本地文件服务**（`local` 字段）：

   - 静态文件托管
   - 自动查找 index.html/index.htm
   - 支持通配符路径映射
   - 自动设置 Content-Type
   - 支持 `to.headers` 自定义响应头
2. **代理转发服务**（`to` 字段）：

   - 转发到远程 API
   - **支持完整的 `from` 和 `to` 对象配置**
   - **与独立 listen 和主代理功能完全一致**

   **from 支持的所有功能**：

   - ✅ `method` - HTTP 方法过滤
   - ✅ `headers` - 请求头修改（支持数组和随机选择）
   - ✅ `querystring` - 查询参数添加/删除
   - ✅ `proxy` - 代理服务器配置（暂不支持）
   - ✅ `match` - 正则提取请求体
   - ✅ `replace` - 替换请求体内容

   **to 支持的所有功能**：

   - ✅ `headers` - 响应头修改（覆盖默认跨域头）
   - ✅ `match` - 正则提取响应体
   - ✅ `replace` - 替换响应体内容

   **其他功能**：

   - ✅ OPTIONS 预检请求自动处理
   - ✅ 自定义跨域配置
   - ✅ 请求/响应体脱敏

#### 优势

1. **简化配置**：多个相对路径 mapping 共用一个端口，无需为每个路径配置独立端口
2. **避免污染**：相对路径不会污染主代理规则，主代理专注于 URL 转发
3. **统一管理**：所有相对路径服务在同一个服务器上，便于管理和监控
4. **功能完整**：支持本地文件和代理转发两种模式，满足不同需求

### From 配置

`from` 字段定义请求的匹配规则和请求处理方式。

#### 字符串格式

```json
{
  "from": "https://api.example.com/v1*"
}
```

#### 对象格式

```json
{
  "from": {
    "url": "https://api.example.com/v1*",
    "headers": {
      "Authorization": "Bearer token",
      "X-Custom-Header": "value"
    },
    "match": "\"request\":\\s*\\{([^}]+)\\}",
    "replace": {
      "oldValue": "newValue"
    }
  }
}
```

**字段说明**：

- `url`（必需）：匹配的 URL 模式
  - 支持 `*` 通配符
  - 支持正则表达式（包含 `(`, `[`, `{`, `^`, `$`, `|` 时）
- `headers`（可选）：要添加或覆盖的请求头
  - 值可以是字符串或字符串数组
  - **特殊功能**：`Authorization` 字段支持数组，每次请求随机选择一个（实现负载均衡）
  - **移除功能**：值为 `null` 时，删除该 header（不传给下游）
- `querystring`（可选）：要添加或覆盖的查询参数
  - 值为字符串时，设置或覆盖该参数
  - **移除功能**：值为 `null` 时，删除该参数（不传给下游）
- `proxy`（可选）：代理服务器配置，支持多种格式
  - **单个字符串**：`"http://user:pass@proxy.com:8080"` 或 `"socks5://user:pass@proxy.com:1080"`
  - **字符串数组**：`["http://proxy1.com:8080", "http://proxy2.com:8080"]`，每次请求随机选择一个
  - **本地文件路径**：`"./proxy_list.txt"`，从文件读取代理列表（每行一个）
  - **远程 URL**：`"https://example.com/proxies.txt"`，每 5 分钟自动更新代理列表
- `match`（可选）：正则表达式，从请求体中提取内容
- `replace`（可选）：键值对，替换请求体中的内容

### To 配置

`to` 字段定义目标地址和响应处理方式。

#### 字符串格式

```json
{
  "to": "https://backend.example.com/api/v1*"
}
```

#### 对象格式

```json
{
  "to": {
    "url": "https://backend.example.com/api/v1*",
    "headers": {
      "Access-Control-Allow-Origin": "https://trusted-site.com",
      "X-Response-Header": "value"
    },
    "match": "\"data\":\\s*\\{([^}]+)\\}",
    "replace": {
      "internalName": "publicName"
    }
  }
}
```

**字段说明**：

- `url`（必需）：目标 URL
- `headers`（可选）：要添加或覆盖的响应头（**优先级最高，覆盖默认跨域头**）
  - **移除功能**：值为 `null` 时，删除该响应头
- `match`（可选）：正则表达式，从响应体中提取内容
- `replace`（可选）：键值对，替换响应体中的内容

### 其他配置项

#### Local - 本地文件服务

```json
{
  "from": "/static/*",
  "local": "./static/*"
}
```

#### Listen - 专用端口监听

```json
{
  "from": "https://api.example.com/*",
  "to": "https://backend.example.com/*",
  "listen": 8081
}
```

或使用对象格式配置 HTTPS：

```json
{
  "from": "https://local.dev/*",
  "local": "./static/*",
  "listen": {
    "port": 8443,
    "cert": "auto"
  }
}
```

或指定证书文件：

```json
{
  "listen": {
    "port": 8443,
    "cert": {
      "cert": "./.cert/server.crt",
      "key": "./.cert/server.key"
    }
  }
}
```

#### CC - Carbon Copy（请求复制）

```json
{
  "from": "https://api.example.com/*",
  "to": "https://backend.example.com/*",
  "cc": [
    "http://backup-server.com/api",
    "http://analytics-server.com/track"
  ]
}
```

## 🎓 使用示例

### 示例 1：API 密钥注入

为所有请求自动添加 API 密钥：

```json
{
  "from": {
    "url": "https://api.example.com/*",
    "headers": {
      "Authorization": "Bearer your-secret-token",
      "X-API-Key": "your-api-key"
    }
  },
  "to": "https://backend.example.com/*"
}
```

### 示例 2：Authorization 数组随机负载均衡

当配置多个 API Token 时，代理会在每次请求时随机选择一个，实现简单的负载均衡：

```json
{
  "from": {
    "url": "https://api.openai.com/v1*",
    "headers": {
      "Authorization": [
        "Bearer sk-proj-token1-xxxxxxxxxxxxxx",
        "Bearer sk-proj-token2-yyyyyyyyyyyyyy",
        "Bearer sk-proj-token3-zzzzzzzzzzzzzz"
      ],
      "User-Agent": "Custom-Proxy/1.0"
    }
  },
  "to": "https://api.openai.com/v1*"
}
```

**功能说明**：

- `Authorization` 可以是字符串或字符串数组
- 当配置为数组时，每次请求会随机选择一个值
- 适用于多个 API Key 轮询使用，避免单一 Key 限流
- 日志会显示选择的是第几个 Token（已脱敏）

**日志示例**：

```
[RANDOM AUTH] Selected Authorization [2/3]: Bearer sk-***-yyyyyy
[REQUEST HEADERS] Applying 2 custom headers from 'from' config
[REQUEST HEADERS]   Authorization: Bearer sk-***-yyyyyy
[REQUEST HEADERS]   User-Agent: Custom-Proxy/1.0
```

### 示例 3：请求体数据脱敏

在发送请求前替换敏感信息：

```json
{
  "from": {
    "url": "https://api.example.com/submit",
    "replace": {
      "\"password\":\"[^\"]+\"": "\"password\":\"***\"",
      "\"credit_card\":\"[^\"]+\"": "\"credit_card\":\"****\""
    }
  },
  "to": "https://backend.example.com/submit"
}
```

### 示例 4：响应数据转换

修改响应内容：

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "replace": {
      "OldBrand": "NewBrand",
      "old-logo.png": "new-logo.png"
    }
  }
}
```

### 示例 5：双向数据处理

同时处理请求体和响应体：

```json
{
  "from": {
    "url": "https://api.transform.com/*",
    "match": "\"request\":\\s*\\{([^}]+)\\}",
    "replace": {
      "\"oldField\"": "\"newField\""
    }
  },
  "to": {
    "url": "https://backend.transform.com/*",
    "match": "\"response\":\\s*\\{([^}]+)\\}",
    "replace": {
      "internal-data": "public-data"
    }
  }
}
```

### 示例 6：正则表达式 URL 映射

使用正则表达式进行动态 URL 转换：

```json
{
  "from": "https://api\\.example\\.com/v(\\d+)/users/(\\d+)",
  "to": "https://backend.example.com/api/v$1/user/$2"
}
```

**效果**：

- `https://api.example.com/v2/users/123` → `https://backend.example.com/api/v2/user/123`

### 示例 8：QueryString 参数处理

添加、修改或移除查询参数：

```json
{
  "from": {
    "url": "https://api.example.com/search*",
    "querystring": {
      "api_key": "my-custom-key",
      "format": "json",
      "debug": null,
      "trace": null
    }
  },
  "to": "https://backend.example.com/search*"
}
```

**效果**：

- 添加/覆盖 `api_key` 和 `format` 参数
- 移除 `debug` 和 `trace` 参数

### 示例 9：Headers 移除功能

移除不需要的请求头和响应头：

```json
{
  "from": {
    "url": "https://api.example.com/data*",
    "headers": {
      "X-Debug-Mode": null,
      "X-Internal-Token": null,
      "Authorization": "Bearer new-token"
    }
  },
  "to": {
    "url": "https://backend.example.com/data*",
    "headers": {
      "Server": null,
      "X-Powered-By": null
    }
  }
}
```

**效果**：

- 移除请求中的调试相关 headers
- 移除响应中的服务器信息 headers

### 示例 10：使用 HTTP/SOCKS5 代理

#### 单个代理

```json
{
  "from": {
    "url": "https://api.openai.com/v1*",
    "headers": {
      "Authorization": "Bearer sk-your-token"
    },
    "proxy": "http://proxy-user:proxy-pass@proxy.example.com:8080"
  },
  "to": "https://api.openai.com/v1*"
}
```

#### SOCKS5 代理

```json
{
  "from": {
    "url": "https://api.anthropic.com/v1*",
    "headers": {
      "x-api-key": "sk-ant-your-key"
    },
    "proxy": "socks5://user:pass@socks-proxy.example.com:1080"
  },
  "to": "https://api.anthropic.com/v1*"
}
```

### 示例 11：代理数组随机负载均衡

```json
{
  "from": {
    "url": "https://api.example.com/v1*",
    "headers": {
      "Authorization": "Bearer token"
    },
    "proxy": [
      "http://proxy1.example.com:8080",
      "http://proxy2.example.com:8080",
      "http://proxy3.example.com:8080"
    ]
  },
  "to": "https://backend.example.com/v1*"
}
```

**功能说明**：

- 配置多个代理服务器
- 每次请求随机选择一个代理
- 实现代理级别的负载均衡

### 示例 12：从文件读取代理列表

创建 `proxy_list.txt` 文件：

```
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:8080
socks5://proxy3.example.com:1080
# 这是注释，会被忽略
http://proxy4.example.com:8080
```

配置文件：

```json
{
  "from": {
    "url": "https://api.example.com/v1*",
    "headers": {
      "Authorization": "Bearer token"
    },
    "proxy": "./proxy_list.txt"
  },
  "to": "https://backend.example.com/v1*"
}
```

### 示例 13：从远程 URL 获取代理（自动更新）

```json
{
  "from": {
    "url": "https://api.example.com/v1*",
    "headers": {
      "Authorization": "Bearer token"
    },
    "proxy": "https://proxy-provider.example.com/proxies.txt"
  },
  "to": "https://backend.example.com/v1*"
}
```

**功能说明**：

- 从远程 URL 获取代理列表
- 每 5 分钟自动更新代理列表
- 支持 `.txt` 和 `.json` 格式（路径后缀判断）
- 适用于使用代理服务提供商的场景

### 示例 14：双重随机负载均衡

同时使用 Authorization 数组和 Proxy 数组：

```json
{
  "from": {
    "url": "https://api.openai.com/v1*",
    "headers": {
      "Authorization": [
        "Bearer sk-proj-token1",
        "Bearer sk-proj-token2",
        "Bearer sk-proj-token3"
      ]
    },
    "proxy": [
      "http://proxy1.example.com:8080",
      "http://proxy2.example.com:8080"
    ]
  },
  "to": "https://api.openai.com/v1*"
}
```

**效果**：

- 每次请求随机选择一个 API Token
- 每次请求随机选择一个代理服务器
- 实现双重负载均衡和隐私保护

### 示例 15：自定义 CORS 配置

覆盖默认跨域头，限制特定域访问：

```json
{
  "from": "https://api.example.com/*",
  "to": {
    "url": "https://backend.example.com/*",
    "headers": {
      "Access-Control-Allow-Origin": "https://trusted-site.com",
      "Access-Control-Allow-Methods": "GET, POST",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Credentials": "true"
    }
  }
}
```

### 示例 16：公共服务器 - 本地文件服务

使用公共服务器托管静态文件：

```json
{
  "server": {
    "port": 3000,
    "cert": "auto"
  },
  "mappings": [
    {
      "from": "/assets/*",
      "local": "./public/assets/*"
    },
    {
      "from": "/app/*",
      "local": "./dist/*"
    }
  ]
}
```

**访问方式**：

- `https://localhost:3000/assets/logo.png` → `./public/assets/logo.png`
- `https://localhost:3000/app/` → `./dist/index.html`（自动查找）

### 示例 17：公共服务器 - 代理转发（完整功能）

使用公共服务器转发 API 请求，支持所有高级功能：

```json
{
  "server": {
    "port": 3000
  },
  "mappings": [
    {
      "comment": "简单代理转发",
      "from": "/api/*",
      "to": "https://backend.example.com/api/*"
    },
    {
      "comment": "带认证和响应头的代理",
      "from": {
        "url": "/secure-api/*",
        "method": ["GET", "POST"],
        "headers": {
          "Authorization": "Bearer secret-token",
          "X-API-Version": "v2"
        }
      },
      "to": {
        "url": "https://secure-backend.com/*",
        "headers": {
          "Access-Control-Allow-Origin": "https://myapp.com",
          "X-Response-Time": "fast"
        }
      }
    },
    {
      "comment": "完整功能：headers + querystring + match + replace",
      "from": {
        "url": "/transform/*",
        "method": ["POST", "PUT"],
        "headers": {
          "Authorization": [
            "Bearer token1",
            "Bearer token2",
            "Bearer token3"
          ],
          "Content-Type": "application/json",
          "X-Debug": null
        },
        "querystring": {
          "api_key": "my-secret-key",
          "version": "2024",
          "debug": null
        },
        "match": "\"request\":\\s*\\{([^}]+)\\}",
        "replace": {
          "sensitive-field": "***",
          "\"password\":\"[^\"]+\"": "\"password\":\"***\""
        }
      },
      "to": {
        "url": "https://transform-backend.com/*",
        "headers": {
          "Access-Control-Allow-Origin": "https://trusted-app.com",
          "X-Powered-By": "MyProxy",
          "Server": null
        },
        "match": "\"data\":\\s*\\{([^}]+)\\}",
        "replace": {
          "internal-key": "public-key",
          "secret-value": "***"
        }
      }
    }
  ]
}
```

**功能说明**：

- ✅ **Method 过滤**：限制特定 HTTP 方法
- ✅ **Headers 修改**：请求头注入/删除，响应头自定义
- ✅ **QueryString 处理**：添加/覆盖/删除查询参数
- ✅ **Authorization 随机**：支持多个 token 负载均衡
- ✅ **Match 提取**：正则提取请求/响应体特定内容
- ✅ **Replace 替换**：脱敏敏感信息，修改内容
- ✅ **自定义跨域**：覆盖默认跨域配置
- ✅ **OPTIONS 处理**：自动处理预检请求

**访问方式**：

- `http://localhost:3000/api/users` → `https://backend.example.com/api/users`
- `http://localhost:3000/secure-api/data` → `https://secure-backend.com/data`（带认证）
- `http://localhost:3000/transform/process` → `https://transform-backend.com/process`（完整处理）

### 示例 18：Method 字段使用

限制特定 HTTP 方法：

```json
{
  "from": {
    "url": "https://api.example.com/data*",
    "method": "GET"
  },
  "to": "https://readonly-backend.com/data*"
}
```

或支持多个方法：

```json
{
  "from": {
    "url": "https://api.example.com/users*",
    "method": ["GET", "POST", "PUT"]
  },
  "to": "https://backend.com/users*"
}
```

## 🔧 高级功能

### 正则表达式匹配

#### URL 正则匹配

当 `from.url` 包含正则表达式特征字符（`(`, `[`, `{`, `^`, `$`, `|`）时，会自动尝试正则匹配：

```json
{
  "from": "https://old-api\\.example\\.com/(v\\d+)/(.*)",
  "to": "https://new-api.example.com/$1/$2"
}
```

**说明**：

- 使用 `\.` 匹配字面点号
- 使用 `()` 创建捕获组
- 使用 `$1`, `$2` 引用捕获组

#### 内容正则匹配

`match` 和 `replace` 字段都支持正则表达式：

```json
{
  "from": {
    "url": "https://api.example.com/*",
    "match": "\"data\":\\s*\\{([^}]+)\\}",
    "replace": {
      "\"status\":\"(\\w+)\"": "\"status\":\"modified-$1\""
    }
  }
}
```

### 请求/响应处理流程

#### 请求处理流程

1. 接收客户端请求
2. 匹配 `from.url`（支持字符串/正则）
3. 应用 `from.match` 提取请求体内容
4. 应用 `from.replace` 替换请求体
5. 应用 `from.headers` 设置请求头
6. 发送到目标服务器

#### 响应处理流程

1. 接收目标服务器响应
2. 复制源站响应头
3. 应用默认 CORS 跨域头
4. 应用 `to.headers` 设置响应头（**覆盖之前的头**）
5. 应用 `to.match` 提取响应体内容
6. 应用 `to.replace` 替换响应体
7. 返回给客户端

### 默认 CORS 跨域头

代理工具默认会为所有响应设置以下跨域头：

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

**重要**：使用 `to.headers` 可以覆盖这些默认值。

### OPTIONS 请求处理

所有 `OPTIONS` 预检请求会自动：

1. 返回 `200 OK` 状态码
2. 应用默认 CORS 跨域头
3. 不转发到目标服务器

## 📝 日志说明

代理工具会输出详细的日志信息：

### 日志类型

```
[DEBUG] - 调试信息（URL 匹配过程）
[RANDOM AUTH] - Authorization 随机选择
[REQUEST QUERY] - 查询参数处理
[REQUEST MATCH] - 请求体匹配提取
[REQUEST REPLACE] - 请求体内容替换
[REQUEST HEADERS] - 请求头设置/移除
[RESPONSE HEADERS] - 响应头设置/移除
[RESPONSE MATCH] - 响应体匹配提取
[RESPONSE REPLACE] - 响应体内容替换
[OPTIONS] - OPTIONS 请求处理
[CC] - Carbon Copy 请求复制
```

### 日志示例

```
[DEBUG] Trying to match: https://api.example.com/v2/users/123 with pattern: https://api\.example\.com/v(\d+)/users/(\d+)
[DEBUG] ✓ Regex matched! https://api.example.com/v2/users/123 -> https://backend.example.com/api/v2/user/123
[REQUEST MATCH] Extracted 256 bytes from request body
[REQUEST REPLACE] Applied replacement: oldField -> newField
[REQUEST HEADERS] Applying 2 custom headers from 'from' config
[REQUEST HEADERS]   Authorization: Bearer ***
[REQUEST HEADERS]   X-API-Key: ***
[GET] https://api.example.com/v2/users/123 -> https://backend.example.com/api/v2/user/123 (MAPPED)
[RESPONSE HEADERS] Applying 3 custom headers from 'to' config
[RESPONSE HEADERS]   Access-Control-Allow-Origin: https://trusted-site.com
[RESPONSE HEADERS]   Cache-Control: max-age=3600
[RESPONSE HEADERS]   X-Powered-By: MyProxy
[RESPONSE MATCH] Extracted 1024 bytes from response body
[RESPONSE REPLACE] Applied replacement: internal-data -> public-data
[GET] https://api.example.com/v2/users/123 - 200 (1024 bytes)
```

## ⚠️ 注意事项

### 性能考虑

1. **正则表达式复杂度**：复杂的正则表达式会影响性能，建议：

   - 避免使用过于复杂的表达式
   - 测试正则表达式的性能
   - 考虑使用简单的字符串匹配
2. **请求/响应体处理**：

   - `match` 和 `replace` 需要读取完整的请求/响应体
   - 对大文件可能影响性能
   - 建议只在必要时使用

### 安全注意

1. **证书信任**：使用自动生成的证书时，需要：

   - 将根证书导入系统信任列表
   - 或在浏览器中添加例外
2. **敏感信息**：

   - 配置文件可能包含 API 密钥等敏感信息
   - 建议使用环境变量或密钥管理工具
   - 不要将包含敏感信息的配置文件提交到版本控制
3. **CORS 配置**：

   - 默认的 `Access-Control-Allow-Origin: *` 允许所有域访问
   - 生产环境建议使用 `to.headers` 限制特定域

### 配置建议

1. **规则验证**：

   - ✅ **`from` 字段是必需的**，缺失或为空会导致规则被跳过
   - ✅ **`to` 和 `local` 至少需要一个**，两者都缺失会导致规则被跳过
   - ✅ **`method` 字段是可选的**，不配置时匹配所有 HTTP 方法
   - ⚠️ 启动时查看日志，确认所有规则都已成功加载
   - ⚠️ 日志会显示 `Loaded X valid mapping rules (filtered from Y total)` 来指示过滤情况
2. **Match 行为**：

   - `match` 字段使用正则表达式的第一个捕获组 `()` 作为提取结果
   - 如果没有匹配，返回空内容（不是原始内容）
   - 建议只在确实需要提取特定部分时使用
3. **Replace 顺序**：

   - `replace` 的键值对按配置顺序依次应用
   - 后面的替换可能会影响前面替换的结果
   - 建议按照逻辑顺序组织替换规则
4. **Headers 优先级**：

   - `to.headers` 的优先级最高，会覆盖默认 CORS 头和源站响应头
   - 使用 `null` 值可以删除不需要的 header
   - Authorization 数组会随机选择，每次请求可能使用不同的值
5. **相对路径 Mapping**：

   - 相对路径 mapping（from 以 `/` 开头）需要配置 `server` 才能工作
   - 可以使用 `local`（本地文件）或 `to`（代理转发）
   - 相对路径 mapping 支持所有高级功能（headers、match、replace、method 等）
   - 公共服务器会自动处理 OPTIONS 请求
6. **Method 过滤**：

   - 只在需要限制特定方法时配置 `method`
   - **不配置时默认匹配所有方法**（GET、POST、PUT、DELETE 等）
   - 方法名不区分大小写
7. **性能优化**：

   - 避免在高流量接口使用复杂的正则表达式
   - Match/Replace 需要读取完整请求/响应体，对大文件有性能影响
   - 代理数组和 Authorization 数组的随机选择是线程安全的

## 📚 完整配置示例

```json
{
  "server": {
    "port": 3000,
    "cert": "auto"
  },
  "mappings": [
    {
      "comment": "公共服务器 - 静态文件托管",
      "from": "/static/*",
      "local": "./public/*"
    },
    {
      "comment": "公共服务器 - API 代理转发",
      "from": {
        "url": "/api/*",
        "method": ["GET", "POST"],
        "headers": {
          "X-Custom-Header": "value"
        }
      },
      "to": {
        "url": "https://backend.example.com/*",
        "headers": {
          "Access-Control-Allow-Origin": "https://myapp.com"
        }
      }
    },
    {
      "comment": "独立端口 - 完整配置示例",
      "from": {
        "url": "https://api.openai.com/v1*",
        "method": "POST",
        "headers": {
          "Authorization": [
            "Bearer sk-token1",
            "Bearer sk-token2",
            "Bearer sk-token3"
          ],
          "User-Agent": "MyApp/1.0"
        },
        "querystring": {
          "version": "2024",
          "debug": null
        },
        "proxy": ["http://proxy1.com:8080", "http://proxy2.com:8080"],
        "match": "\"request\":\\s*\\{([^}]+)\\}",
        "replace": {
          "sensitive-data": "***"
        }
      },
      "to": {
        "url": "https://api.openai.com/v1*",
        "headers": {
          "Access-Control-Allow-Origin": "https://trusted.com",
          "X-Proxy-Version": "1.0",
          "Server": null
        },
        "match": "\"data\":\\s*\\{([^}]+)\\}",
        "replace": {
          "internal-key": "public-key"
        }
      },
      "listen": {
        "port": 8443,
        "cert": "auto"
      },
      "cc": [
        "http://analytics.example.com/track",
        "http://backup.example.com/store"
      ]
    }
  ]
}
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License
