# Domain Intelligence 审计（实施前）

基线：上游 0be3da7558332df832b473d3f592afd76feeee87，main 分支。工作区已有中文化变更，必须保留。Go 1.26.1；React/Vite 前端经 Docker 构建后由 Go embed；SQLite 保存在现有 /data/netflow.db，原 Open 使用 CREATE IF NOT EXISTS，暂无独立迁移版本表。仓库包含 Go 测试；前端无独立测试脚本。

## 当前识别和风险

Names.Observe 把 DNS A/AAAA 地址映射到单个名称，CNAME 反向表每个目标只保留一个别名，向上最多走八层；后一次观察会覆盖同 IP 的旧名称。Lookup 返回一个名称，Dirty 每小时刷新一次时间戳，恢复只加载现有 dns_names 表。过期是通过数据库保留期清理，不代表连接的逐客户端 DNS 溯源。共享 CDN 的一个 IP 可能关联多个应用，现有单名称记录不能证明具体连接归属，必须默认保守处理。

Engine.destOf 先处理站点和本地流量，再按 IP 查 DNS，执行 RegisteredDomain（刻意忽略私有后缀），否则 ASN，再退回 IP。dest 字典按 key 分配稳定整数 ID；rollup_1m、rollup_1h、conns 引用该 ID。历史原始名称仅在 conns.remote_name 保留，因此不得批量重写旧 ID 或宣称能够恢复历史 FQDN。应用规则应在注册域名归并之前执行；遇到不明确的共享地址保留原有归并回退。

## 可复用与设计

- 复用 Names、publicsuffix、目的地址字典、单库 SQLite、现有鉴权、HTTP JSON 辅助和 React 组件。
- 扩展 Names 为有限候选集合，保留旧 Lookup/Restore/Dirty 接口，并增加候选持久化；CNAME 循环要限制，不能把多别名压成一个。
- 使用反向标签 Trie；精确匹配、后缀、排除、用户覆盖及同优先级冲突需要确定性；对共享 IP 存在未知或多个应用时不归类。
- 迁移新增 app_catalog、domain_rules、dns_name_candidates、domain_source_state、domain_update_runs 与版本快照；单独 schema 版本、事务和迁移前 SQLite 一致性备份，不修改已有流量表。
- 新增 API 经 Server.auth 和 readJSON；限制请求体并使用参数化 SQL；未知榜基于历史 dests/rollup 查询，只能承诺注册域名粒度。
- 前端新增 Domain Intelligence 页面，使用现有中文词典和语言设置，不改路由器、网络、端口、Docker 架构或已有历史。
- V2Fly 上游仓库 MIT，必须固定快照、校验并保留许可证，include 的属性筛选必须正确处理；不能把关键词或泛分类当应用。MetaCubeX README 指出数据包含 Blackmatrix7 内容，来源及许可证未厘清，跳过自动分发。
- 每周调度应在 Go 进程内，更新候选版本先验证再原子切换，保存失败时保留旧版并隔离用户规则。

## 拟改文件

新增 internal/enrich/domainmatcher.go、domain-source 及其测试；internal/store 域名迁移/规则/查询实现；internal/api 认证接口；web/src 页面与导航；cmd 启动调度（如需要）；domain-library 目录和文档。必要时在 internal/engine/engine.go 的目的地址归并前接入。保留现有 Dockerfile，不修改采集、解码、流量方向、设备、WAN、告警和生产部署。

## 验收边界

当前主机未发现 Go 或 Docker 命令；必须明确区分本地与在线运行的检查，不能报告未执行的测试通过。Docker 构建和隔离容器健康检查需要可用 Docker 环境；不得影响现有生产容器。

## 进展更新
已从 Go 官方发行包在临时目录准备项目所需 Go 1.26.1，不改变系统全局版本；Docker 命令仍不可用。首轮匹配器和 V2Fly 纯文本解析器已在隔离状态下通过 internal/enrich 单元测试，尚未接入实时引擎或运行上游自动下载。

## 后续进展与运行边界

DNS 多候选现与引擎刷盘、恢复及应用匹配管线接通。首次迁移创建 SQLite 一致性备份；写入失败保留候选以便重试。共享 IP 的候选存在未知、冲突或溢出时，应用匹配失败并沿用原目标分类。旧版单名称记录不能证明候选完整，恢复时按不完整处理。历史聚合记录不重分类。

内置核心规则目前只是未逐条核验来源的样例，因此不自动启用；正式来源、版本和许可证完成验证前，不应把样例的 high 标记视为已审核结论。RouterOS DNS 缓存也不能证明某个连接对应哪个客户端查询，即使候选一致，识别仍是基于观测数据的推断。用户规则 API、上游下载校验和自动更新、回滚、管理页面及真实旧库验收尚未完成。

## 用户规则与历史域名排行

已新增受现有登录鉴权保护的用户规则列表、创建、修改和删除接口，以及双语规则管理页。创建或修改时验证规范化域名、公共后缀、匹配方式、应用 ID 和启用规则的冲突；规则仅在持久化成功后热加载。用户规则不被自动来源覆盖，重启后恢复。当前可选择的应用来自内置的 16 项应用目录，尚不支持新增应用；内置自动规则仍未启用。历史排行只查询小时汇总中当时以域名归类的前 50 项，约 7 天，不代表完整 DNS 查询或按新规则重新分类的结果。

## 已核验的最小内置规则（2026-11-17）

从 V2Fly domain-list-community 固定提交 `41504eae2a11f305fe88cfc605cf6c105a80bf5a` 对照对应应用清单，仅启用应用专属的 `youtube.com`、`netflix.com`、`bilibili.com`、`github.com` 和 `spotify.com`。这些条目保留来源版本；MIT 许可文本随程序嵌入。其余样例仍不启用。参考：https://github.com/v2fly/domain-list-community/tree/41504eae2a11f305fe88cfc605cf6c105a80bf5a/data 。这不是完整上游导入，亦不代表每周更新和回滚已经实现。

匹配只根据观测到的 RouterOS DNS 缓存推断；缓存未覆盖的直连、自有 DNS 或 DNS over HTTPS 等流量不能可靠归因。CNAME 终点与独立查询的证据在当前数据中无法可靠区分，未知的终点仍会阻止应用归类，宁可漏判也不猜测。新规则只作用于之后创建的连接；已存在连接保持原始目的地，历史累计与汇总口径保持一致。DNS 时间按小时向上取整，候选有效期保守延长不超过一小时，以减少重复写入。
