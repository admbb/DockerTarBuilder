import zh from './zh-CN.json';

const key = 'netflow-plus-language';
export function isChinese(): boolean {
  try { return localStorage.getItem(key) !== 'en'; } catch { return true; }
}
/** Only call for text authored by the application, never device/flow data. */
export function ui(text: string): string {
  return isChinese() ? (zh as Record<string, string>)[text] ?? text : text;
}
const errors: Record<string, string> = {
  'login required': '请先登录。', 'wrong password': '密码不正确。',
  'cross-site request refused': '跨站请求被拒绝。', 'invalid JSON body': '请求数据格式无效。',
  'not found': '请求的内容不存在。', 'name is too long': '名称过长。',
  'the webhook must be an http:// or https:// URL': 'Webhook 必须使用 http:// 或 https:// 地址。',
  'internal error': '服务器内部错误。', 'Failed to fetch': '无法连接服务器。',
};
/** Unknown backend or router messages are preserved for diagnosis. */
export function displayError(message: string): string {
  return isChinese() ? errors[message] ?? message : message;
}
export function switchLanguage(): void {
  try { localStorage.setItem(key, isChinese() ? 'en' : 'zh-CN'); } catch { /* still reload */ }
  window.location.reload();
}
