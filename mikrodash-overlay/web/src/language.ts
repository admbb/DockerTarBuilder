import { extraLabels } from './language-extra';

// Translations are deliberately limited to authored labels, never router data,
// select options, commands, or values. Add entries as individual UI is audited.
const labels: Record<string, string> = {
  'Dashboard': '仪表盘', 'Network': '网络', 'Wireless': '无线网络',
  'IP Services': 'IP 服务', 'Routing': '路由', 'Security': '安全',
  'System': '系统', 'Devices': '设备', 'Interfaces': '网络接口',
  'Topology': '网络拓扑', 'Bridges': '网桥', 'Wifi Networks': 'Wi-Fi 网络',
  'Wifi Clients': 'Wi-Fi 客户端', 'Wifi Map': 'Wi-Fi 地图',
  'Firewall': '防火墙', 'Address Lists': '地址列表', 'Certificates': '证书',
  'Security Scan': '安全扫描', 'Connections': '连接', 'Traffic': '流量',
  'Bandwidth': '带宽', 'Queues': '队列', 'Logs': '日志',
  'Users': '用户', 'Services': '服务', 'Packages': '软件包',
  'Scripts': '脚本', 'Scheduler': '计划任务', 'Files': '文件',
  'Containers': '容器', 'Tools': '工具', 'Terminal': '终端',
  'AI Agent': 'AI 助手', 'Reports': '报告', 'Backups': '备份',
  'Audit Trail': '审计日志', 'Settings': '设置', 'General': '常规',
  'Authentication': '身份验证', 'Access Management': '访问权限管理',
  'Notification channels': '通知渠道', 'Message Templates': '消息模板',
  'Data Retention': '数据保留', 'Limits': '限制', 'Poll Intervals': '轮询间隔',
  'Theme': '主题', 'Branding': '品牌', 'Fonts': '字体', 'Visible Pages': '显示的页面',
  'System Prompt': '系统提示词', 'Rule Counts': '规则数量',
  'Action Breakdown': '动作分布', 'Chain Count': '链数量',
  'Interface Types': '接口类型', 'Physical Ports': '物理端口',
  'Subnets': '子网', 'IP Utilisation': 'IP 使用率', 'DHCP Leases': 'DHCP 租约',
  'Top Talkers': '流量排行', 'API Diagnostics': 'API 诊断',
  'Agent Overview': 'AI 助手概览', 'Security Score': '安全评分',
  'Connections Map': '连接地图', 'Top Countries': '国家或地区排行',
  'Connection Flow': '连接流向', 'Top Ports': '端口排行',
  'Firewall Actions': '防火墙动作', 'Signal Health': '信号质量',
  'Interface Lists': '接口列表', 'Routing Tables': '路由表',
  'Routing Rules': '路由规则', 'DHCP Clients': 'DHCP 客户端',
  'DHCP Servers': 'DHCP 服务器', 'Apps Usage': '应用流量',
  'Notifications': '通知', 'Appearance': '外观', 'Provisioning': '设备部署',
  'Features': '功能', 'About': '关于', 'NTP Client': 'NTP 客户端',
  'Clock': '时钟', 'Logging': '日志设置', 'SNMP': 'SNMP',
  'Members': '成员', 'Lists': '列表', 'Servers': '服务器', 'Networks': '网络',
  'Rules': '规则', 'Actions': '动作', 'Communities': '团体', 'Transfer': '传输',
  'Peers': '对等端', 'Envs': '环境变量', 'Mounts': '挂载',
  'Last hour': '最近一小时', '24 hours': '24 小时', '7 days': '7 天', '30 days': '30 天',
  'Total': '总流量', 'Apps': '应用', 'Top app': '流量最高的应用', 'Unnamed': '未识别',
  'App': '应用', 'Category': '类别', 'Share': '占比', 'Waiting for traffic': '正在等待流量数据',
};

const fieldLabels: Record<string, string> = {
  name: '名称', list: '列表', interface: '接口', interfaces: '接口', address: '地址',
  addresses: '地址', gateway: '网关', disabled: '已禁用', dynamic: '动态', invalid: '无效',
  inactive: '未激活', enabled: '已启用', running: '运行中', comment: '备注',
  include: '包含', exclude: '排除', builtin: '内置', port: '端口', proto: '协议',
  availableFrom: '允许访问的来源', remote: '远程地址', commonName: '通用名称',
  privateKey: '私钥', publicKey: '公钥', trusted: '受信任', invalidAfter: '失效时间',
  expiresAfter: '到期时间', owner: '所有者', policy: '策略', runCount: '运行次数',
  lastStarted: '上次运行时间', startTime: '开始时间', interval: '间隔', nextRun: '下次运行',
  mode: '模式', servers: '服务器', status: '状态', syncedServer: '同步服务器',
  systemOffset: '系统偏差', minPoll: '最小轮询间隔', maxPoll: '最大轮询间隔',
  time: '时间', date: '日期', timeZoneName: '时区', timeZoneAutodetect: '自动检测时区',
  gmtOffset: 'GMT 偏移', dstActive: '夏令时生效', topics: '主题', action: '动作',
  prefix: '前缀', isDefault: '默认', target: '目标', memoryLines: '内存行数',
  contact: '联系人', location: '位置', trapTarget: 'Trap 目标', trapVersion: 'Trap 版本',
  engineId: '引擎 ID', security: '安全', readAccess: '读取权限', writeAccess: '写入权限',
  type: '类型', size: '大小', lastModified: '最后修改时间', fib: '转发表',
  srcAddress: '源地址', dstAddress: '目标地址', routingMark: '路由标记', table: '路由表',
  addDefaultRoute: '添加默认路由', addressPool: '地址池', leaseTime: '租约时间',
  authoritative: '权威服务器', dnsServer: 'DNS 服务器', domain: '域名',
  remoteImage: '远程镜像', restartCount: '重启次数', startOnBoot: '开机启动',
  src: '源', dst: '目标', key: '键', listenPort: '监听端口',
};

const key = 'mikrodash-language';

export function isChinese(): boolean {
  try { return localStorage.getItem(key) === 'zh-CN'; } catch { return false; }
}

export function translate(original: string, chinese: string): string {
  return isChinese() ? chinese : original;
}

// Use only with application-authored labels, never with router-supplied values.
export function translateLabel(original: string): string {
  return isChinese() ? (labels[original] ?? extraLabels[original] ?? original) : original;
}

export function translateField(key: string, fallback: string): string {
  return isChinese() ? (fieldLabels[key] ?? fallback) : fallback;
}

export function languageSwitcher(): HTMLButtonElement {
  const chinese = isChinese();
  const switcher = document.createElement('button');
  switcher.type = 'button';
  switcher.className = 'sbtn sbtn-sm';
  switcher.textContent = chinese ? 'English' : '简体中文';
  switcher.setAttribute('aria-label', chinese ? 'Switch to English' : '切换到简体中文');
  switcher.addEventListener('click', () => {
    try { localStorage.setItem(key, chinese ? 'en' : 'zh-CN'); } catch { return; }
    location.reload();
  });
  return switcher;
}

export function initLanguage(): void {
  const host = document.querySelector('#sidenav');
  if (!host) return;
  const switcher = languageSwitcher();
  const label = switcher.textContent;
  switcher.textContent = '';
  switcher.style.cssText = 'display:flex;align-items:center;gap:.65rem;width:100%;min-height:44px;flex-shrink:0;padding:0 14px;border:0;border-top:1px solid var(--border);background:transparent;color:var(--text-muted);cursor:pointer;text-align:left;overflow:hidden';
  const icon = document.createElement('span');
  icon.className = 'nav-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = '🌐';
  const caption = document.createElement('span');
  caption.className = 'nav-label';
  caption.textContent = label;
  switcher.append(icon, caption);
  host.append(switcher);
  if (!isChinese()) return;
  document.documentElement.lang = 'zh-CN';
  // Translate only the initial, application-authored HTML. Never observe later
  // router data or translate values inside editors, selects, or terminal output.
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const textNodes: Text[] = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode as Text);
  for (const node of textNodes) {
    const parent = node.parentElement;
    if (!parent || parent.closest('script, style, pre, code, textarea, select, .terminal, .xterm')) continue;
    const value = node.data.trim().replace(/\s+/g, ' ');
    const translated = labels[value] ?? extraLabels[value];
    if (translated) node.data = node.data.replace(/\S[\s\S]*\S|\S/, translated);
  }
  document.querySelectorAll<HTMLElement>('[title], [aria-label], [placeholder]').forEach((element) => {
    if (element.closest('pre, code, .terminal, .xterm')) return;
    for (const attr of ['title', 'aria-label', 'placeholder']) {
      const value = element.getAttribute(attr);
      if (value && (labels[value] ?? extraLabels[value])) element.setAttribute(attr, labels[value] ?? extraLabels[value] ?? value);
    }
  });
  // Only leaf elements in known, static presentation classes are eligible.
  const selector = '.nav-label, h3.card-title, .fw-scard-title, .if-scard-title, .dhcp-card-title, .scard-title, #settingsTabBar > button, #page-apps .stab, #page-apps .tool-card-label, #appsThead th, #page-apps .empty-state';
  document.querySelectorAll<HTMLElement>(selector).forEach((element) => {
    if (element.children.length || element.id) return;
    const original = element.textContent?.trim() ?? '';
    if (Object.hasOwnProperty.call(labels, original)) element.textContent = labels[original] ?? original;
  });
  const appsSearch = document.querySelector<HTMLInputElement>('#appsSearch');
  if (appsSearch) { appsSearch.placeholder = '搜索应用'; appsSearch.setAttribute('aria-label', '搜索应用'); }
  const ai: Record<string, string> = {
    '#aiAgentClear': '清除', '.ai-welcome-title': '询问有关路由器的问题',
    '.ai-suggest-label': '试试这些问题', '#aiProposeReject': '不做更改',
    '#aiProposeApprove': '应用此更改', '#aiAgentSend': '发送',
  };
  for (const [selector, value] of Object.entries(ai)) {
    const node = document.querySelector(selector);
    if (node) node.textContent = value;
  }
  const welcome = document.querySelector('.ai-welcome-text');
  if (welcome) welcome.textContent = '我可以读取配置、检查运行状况，并通过仪表盘使用的工具进行更改，遵循相同的权限、安全检查和审计规则。除非你在设置中关闭确认，否则更改前会先征求同意。';
  const titles = ['路由器安全检查', '运行状况检查', '带宽使用排行', '防火墙检查', '近期问题', '已连接设备'];
  const subtitles = ['检查配置并优先解释最严重的风险', 'CPU、内存、运行时间和异常', '当前哪些设备最繁忙', '发现有风险、重复或缺失的规则', '解释日志中的错误和警告', '按名称和地址查看网络设备'];
  document.querySelectorAll('.ai-suggest-title').forEach((node, i) => { if (titles[i]) node.textContent = titles[i]; });
  document.querySelectorAll('.ai-suggest-sub').forEach((node, i) => { if (subtitles[i]) node.textContent = subtitles[i]; });
  const input = document.querySelector<HTMLTextAreaElement>('#aiAgentInput');
  if (input) input.placeholder = '询问有关此路由器的问题…（Enter 发送，Shift+Enter 换行）';
}
