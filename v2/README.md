# NetFlow Plus V2

V2 使用独立 SQLite 保存 DNS 查询记录和 IPFIX 汇总。仪表盘支持 `1h`、`24h`、`7d`、`30d`，显示 DNS 应用热度、未知域名以及现有 NetFlow Plus 的设备和总流量。可选的独立 IPFIX 接收器按收到数据报的小时汇总采集量，覆盖范围取决于路由器导出和网络交付情况。

DNS 热度按查询次数统计，小时边界可能超出所选时间。DNS 客户端缓存、DoH、共享解析器及上游记录保留时间都可能造成漏记。现有 NetFlow Plus 的逐连接 API 返回累计快照，其中部分小连接会被折叠。应用字节排行只使用 V2 接收的独立 IPFIX 记录，关闭接收器时返回 HTTP 422。

## 构建和启动

在启用 Linux 容器的 Docker Engine 或 Docker Desktop 上，使用 `docker compose` 插件：

```sh
cp .env.example .env
```

在 `.env` 中设置独立强密码 `APP_PASSWORD`。V2 和 Home Assistant 示例使用用户名 `v2`。需要同步时，填写 `OXIDNS_BASE_URL`、`OXIDNS_RECORDER_TAG` 与上游账号密码。需要显示现有汇总时，填写 `NETFLOW_PLUS_BASE_URL` 与上游账号密码。同一数据卷换用另一套 OxiDNS 数据源时，请调整 `OXIDNS_SOURCE_ID`，使同步进度和记录 ID 按源隔离。上游地址留空即可从无外部数据源的状态启动。

默认 Web 地址为 `http://127.0.0.1:18088`。远程浏览器和 Home Assistant 通过受信任的 HTTPS 反向代理访问。Basic Auth 凭据应在本机、受信任网络或 HTTPS 内传输。保管 `.env`，并限制文件的读取权限。

```sh
docker compose config --quiet
docker compose up -d --build --wait
docker compose exec -T netflow-v2 sh -ec 'test "$(id -u)" -ne 0 && test -w /data && test -s /data/app.db'
curl -fsS http://127.0.0.1:18088/healthz
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18088/api/summary
curl -fsS -u v2 http://127.0.0.1:18088/api/summary?range=24h
```

健康端点返回 `{"status":"ok"}`，未认证的 API 请求返回 `401`，最后一条命令提示输入密码并返回摘要。检查摘要中的 `dns_synced_until_ms` 是否逐步推进、`traffic` 是否返回上游汇总，并检查 `docker compose logs --tail=100 netflow-v2`。健康端点只检查 HTTP 进程。真实上游的认证、查询标签以及数据完整性应分别验收。

同一宿主机已有 V2 时，可用 `docker compose -p netflow-v2-smoke --env-file .env.smoke up -d --build --wait` 做隔离测试。用示例创建 `.env.smoke`，设置独立测试密码和未占用的 `HOST_PORT`。对应清理命令为 `docker compose -p netflow-v2-smoke --env-file .env.smoke down -v`，仅对这次的测试项目使用。

V2 使用独立的 `v2-data` 数据卷。首次同步从约 30 天前开始，每轮最多推进 24 小时。`POLL_INTERVAL_SECONDS` 支持 15–3600 秒，默认 60 秒，`DNS_RETENTION_DAYS` 支持 1–365 天，默认 30 天。常规停机用 `docker compose down`，重启后继续使用同一数据卷。`docker compose down -v` 会删除 V2 数据。

## 可选 IPFIX 接收

先完成上述 HTTP 验收，再为容器配置一个独立 UDP 端口。`FLOW_BIND_ADDRESS` 填 Docker 宿主机的局域网地址，默认回环地址可用于本机验证。`FLOW_EXPORTERS` 填路由器的实际导出源 IP，`LOCAL_NETWORKS` 填本地 CIDR 列表，多个值用逗号分隔。可选的 `FLOW_IGNORE_EXPORT_TARGETS` 填旧、新导出目的 `IP:端口`，用于过滤导出报文本身。`FLOW_RETENTION_DAYS` 支持 1–365 天，默认 30 天。

```sh
docker compose -f docker-compose.yml -f docker-compose.ipfix.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.ipfix.yml up -d --build --wait
```

确认宿主机 `FLOW_PORT`（默认 `2056/udp`）可从导出设备访问，并用防火墙仅允许该设备，再在 RouterOS 上添加第二个 IPFIX 导出目标并保留原目标。核对 V2 日志、汇总中的 IPFIX 记录量和采集字节。UDP 接收依赖模板刷新，启动后可能需要等待首批模板。移除第二目标并用基础 Compose 启动，可关闭 V2 接收器。

`/api/apps/top?metric=bytes` 返回收到的 WAN 字节、DNS 证据推断字节、未知字节和原因。推断仅使用经过延迟和重复扫描的 OxiDNS 记录，并检查客户端、IP、DNS 链、TTL 及冲突；不符合条件的流量保持未知。复扫稳定只说明采集器已观察记录的状态，不能证明客户端缓存、DoH、旁路解析或全部流量都被采集。路由器漏包、缺模板、FastTrack 或采样也会影响覆盖。推断以 IPFIX 接收时间分桶，不是进程识别或精确逐包时间。

## Docker Hub 与 Dockge

发布镜像为 `admbb99/netflow-plus-zh:v2`，独立于既有的 `latest`。该镜像使用 `linux/amd64` 架构，适用于 x86_64 主机；其他架构需要自行构建。Dockge 示例是 [compose.dockge.yml](deploy/compose.dockge.yml)，同目录有 [dockge.env.example](deploy/dockge.env.example)。复制环境变量示例为项目目录下的 `.env`，配置独立强密码、OxiDNS 和旧采集器访问凭据。`V2_BIND_ADDRESS` 和 `V2_FLOW_BIND_ADDRESS` 默认为回环地址；需要从局域网访问时设置为 Docker 宿主机的局域网地址，并按需使用 HTTPS 反向代理和防火墙。

验收 V2 容器后，按已授权方案在 RouterOS 上**新增**指向宿主机 `2056/udp` 的 IPFIX 目标，保留现有 `2055/udp` 目标。新采集器的数据只从其启用后开始累积。旧容器、旧数据卷和原有导出目标不受升级替换。

## API 和 Home Assistant

主要端点包括 `/api/summary`、`/api/apps`、`/api/apps/top?metric=dns|bytes`、`/api/apps/{id}/traffic`、`/api/traffic/trend`、`/api/traffic/devices`、`/api/categories`、`/api/unknown`、`/api/devices/top`，以及 `/api/ha/summary`、`/api/ha/top_apps`、`/api/ha/top_devices`、`/api/ha/categories`。支持时间范围的接口接受 `range=1h|24h|7d|30d`，或 `range=custom&from_ms=...&to_ms=...`（最长 30 天）。IPFIX 的自定义时间使用接收时刻的半开区间。

通过 `POST /api/apps` 添加本地应用，`/api/rules` 管理规则，`/api/rules/export` 和 `/api/rules/import` 导出或导入规则。图标可从本地图标库选择或上传经过安全校验的 SVG。`DNS_CORRELATION_WINDOW_SECONDS` 支持 30、60、120，默认 60。Home Assistant 的 [REST 传感器](deploy/home-assistant.example.yaml) 和 [仪表盘](deploy/home-assistant-dashboard.example.yaml)示例需要替换地址与实体 ID。应用流量查询设有 20 秒超时；高流量、长时间窗口环境可能需要缩小范围。

技术审计见 [数据源与架构](docs/audit-and-architecture.zh-CN.md)。域名规则与图标的授权说明保存在 `internal/catalog/` 和 `web/public/icons/`。
