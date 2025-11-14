# Cato Proxy - 高度可配置的本地代理服务器

Cato Proxy 是一个功能强大的本地HTTP/HTTPS代理服务器，专为开发和调试而设计。它允许您通过简单的JSON配置，轻松地将请求从一个地址映射到另一个地址，修改请求和响应，提供本地文件，甚至为您的开发环境自动生成SSL证书。

## 主要功能

*   **URL映射**: 将HTTP/HTTPS请求从一个源地址无缝代理到目标地址。
*   **HTTPS拦截**: 支持中间人（MITM）攻击模式，可以解密、检查和修改HTTPS流量。
*   **动态配置**: 实时监控配置文件，任何更改都会被自动加载，无需重启代理。
*   **专用监听器**: 为特定的代理规则在专用端口上启动独立的HTTP或HTTPS服务器。
*   **SSL/TLS支持**: 支持为专用监听器自动生成SSL证书，或使用您自己的证书文件。
*   **本地文件服务**: 将请求映射到本地文件或整个目录，方便前端开发和调试。
*   **请求修改**: 为代理的请求添加或覆盖自定义的HTTP头。
*   **响应修改**:
    *   **内容匹配**: 使用正则表达式从响应正文中提取特定内容。
    *   **内容替换**: 使用多组正则表达式对响应正文进行查找和替换。
*   **请求抄送 (Carbon Copy)**: 将符合规则的请求异步地复制一份并发送到其他一个或多个指定的URL。
*   **CORS覆盖**: 自动为所有响应设置宽松的跨域资源共享（CORS）头，解决开发中的跨域问题。
*   **流量记录**: 将所有通过代理的流量捕获并保存为HAR（HTTP Archive）文件，以便后续分析。

## 安装与启动

1.  **构建项目**:
    ```bash
    go build
    ```

2.  **启动代理**:
    ```bash
    ./cato-proxy [参数]
    ```

### 命令行参数

*   `--config` 或 `-c`: 指定配置文件的路径。默认为 `config.json`。
*   `--port` 或 `-p`: 指定主代理服务器的监听端口。默认为 `8080`。
*   `--cert-port`: 指定证书下载页面的服务端口。默认为 `9090`。
*   `--dump` 或 `-d`: 指定一个HAR文件的路径，用于保存所有网络流量。

## 配置说明 (`config.json`)

Cato Proxy 的核心功能通过一个名为 `config.json` 的文件进行配置。该文件包含一个 `mappings` 数组，其中每个对象都是一条代理规则。

### 规则参数详解

| 参数      | 类型                        | 说明                                                                                                                                                           |
| :-------- | :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `from`    | `string`                    | **必需**。匹配请求的源URL模式。支持 `*` 通配符。                                                                                                               |
| `to`      | `string`                    | 将请求代理到的目标URL模式。当使用 `local` 时，此参数可选。                                                                                                       |
| `local`   | `string`                    | 将请求映射到本地文件系统。可以是单个文件路径，也可以是带 `*` 的目录路径（例如 `./static/*`）。                                                                    |
| `listen`  | `number` 或 `object`        | 在指定端口上为该规则启动一个专用服务器。可以是端口号，也可以是包含端口和SSL配置的对象。                                                                          |
| `headers` | `object`                    | 一个键值对集合，用于向代理的请求中添加或覆盖HTTP头。                                                                                                             |
| `cc`      | `array` of `string`         | 一个URL地址数组。代理会将匹配的请求异步地抄送到这些地址。                                                                                                        |
| `match`   | `string`                    | 一个正则表达式，用于从响应正文中提取内容。代理将只返回正则表达式的第一个捕获组匹配到的内容。                                                                       |
| `replace` | `object`                    | 一个键值对集合，其中键是正则表达式，值是替换字符串。用于对响应正文（或 `match` 后的结果）进行多次替换。                                                              |

### `listen` 参数的SSL配置

当 `listen` 参数为一个对象时，可以配置SSL：

*   **自动生成证书**:
    ```json
    "listen": {
      "port": 8443,
      "cert": "auto"
    }
    ```
    代理将为客户端请求的域名自动生成并签发证书。

*   **指定证书文件**:
    ```json
    "listen": {
      "port": 8443,
      "cert": {
        "cert": "./.cert/server.crt",
        "key": "./.cert/server.key"
      }
    }
    ```

在SSL模式下，服务器会同时接受HTTP和HTTPS连接。

## 使用案例

### 1. 基本URL映射

将所有对 `api.openai.com` 的请求转发到 `p-q.p-q.co`。

```json
{
  "from": "https://api.openai.com/v1*",
  "to": "https://p-q.p-q.co/v1*"
}
```

### 2. 提供本地静态文件

将所有 `/static/` 路径下的请求映射到本地的 `./static/` 目录。

```json
{
  "from": "/static/*",
  "local": "./static/*"
}
```
*例如，一个对 `/static/css/style.css` 的请求将会返回本地文件 `./static/css/style.css`。*

### 3. 专用监听器与SSL

在 `8083` 端口上启动一个HTTPS服务器，为所有 `local.dev` 的请求提供 `./static/` 目录下的文件，并自动生成SSL证书。

```json
{
  "from": "https://local.dev/*",
  "local": "./static/*",
  "listen": {
    "port": 8083,
    "cert": "auto"
  }
}
```

### 4. 修改响应内容

代理 `codebuddy.ai` 的请求，从返回的HTML中提取标题，并将标题中的 "Google" 替换为 "MyProxy"。

```json
{
  "from": "https://www.codebuddy.ai/v2*",
  "to": "https://p-q.p-q.co/api/ai/v1*",
  "match": "<title>(.*)</title>",
  "replace": {
    "Google": "MyProxy"
  }
}
```

### 5. 请求抄送与自定义头

代理请求，同时添加自定义的 `Authorization` 头，并将请求的副本发送到 `http://localhost:8082/cc`。

```json
{
  "from": "https://api.example.com/data*",
  "to": "https://api.internal/data*",
  "headers": {
    "Authorization": "Bearer your-custom-token"
  },
  "cc": ["http://localhost:8082/cc"]
}