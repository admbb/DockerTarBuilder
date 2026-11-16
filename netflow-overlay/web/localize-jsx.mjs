// Translate application-authored JSX labels only. API values, identifiers,
// user data and RouterOS commands are never rewritten.
import { parse } from '@babel/parser';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const dict = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'src/lib/zh-CN.json'), 'utf8').replace(/^\uFEFF/, ''));
const attrs = new Set(['title','label','sub','note','empty','placeholder','aria-label','alt']);
export default function localizeJsx() {
  return { name: 'localize-authored-jsx', enforce: 'pre', transform(code, id) {
    if (!id.replaceAll('\\', '/').includes('/src/') || !id.endsWith('.tsx')) return null;
    const ast = parse(code, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
    const edits = [];
    const known = s => Object.hasOwn(dict, s);
    const expr = n => {
      if (!n) return;
      if (n.type === 'StringLiteral' && known(n.value)) edits.push([n.start, n.end, '__nfUi(' + JSON.stringify(n.value) + ')']);
      else if (n.type === 'ConditionalExpression') { expr(n.consequent); expr(n.alternate); }
    };
    function visit(n, parent) {
      if (!n || typeof n !== 'object' || !n.type) return;
      if (n.type === 'JSXText') {
        const raw = code.slice(n.start, n.end), value = raw.trim();
        if (known(value)) {
          const prefix = raw.match(/^\s*/)[0], suffix = raw.match(/\s*$/)[0];
          edits.push([n.start, n.end, prefix + '{__nfUi(' + JSON.stringify(value) + ')}' + suffix]);
        }
      } else if (n.type === 'JSXAttribute' && attrs.has(n.name.name) && n.value?.type === 'StringLiteral' && known(n.value.value)) {
        edits.push([n.value.start, n.value.end, '{__nfUi(' + JSON.stringify(n.value.value) + ')}']);
      } else if (n.type === 'JSXExpressionContainer' && (parent?.type !== 'JSXAttribute' || attrs.has(parent.name.name))) {
        expr(n.expression);
      }
      for (const [key, value] of Object.entries(n)) {
        if (key === 'loc' || key === 'extra' || key === 'tokens' || key === 'comments') continue;
        if (Array.isArray(value)) value.forEach(x => visit(x, n));
        else if (value && typeof value === 'object') visit(value, n);
      }
    }
    visit(ast.program, null);
    if (!edits.length) return null;
    edits.sort((a,b)=>b[0]-a[0]);
    for (const [a,b,v] of edits) code=code.slice(0,a)+v+code.slice(b);
    return {code: 'import { ui as __nfUi } from "/src/lib/i18n";\n'+code, map:null};
  }};
}
