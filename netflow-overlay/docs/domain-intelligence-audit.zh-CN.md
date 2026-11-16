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
