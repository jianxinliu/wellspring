// Data-only templates: no expressions, code evaluation or shell expansion.
export type TemplatePart = { literal: string } | { ref: string; format: 'raw' | 'json' | 'uri' };
export function parseTemplate(template: string): TemplatePart[] {
  if (typeof template !== 'string' || Buffer.byteLength(template) > 1024 * 1024) throw new Error('template must be text of at most 1 MiB');
  const parts: TemplatePart[] = [];
  let offset = 0;
  const pattern = /\{\{([\s\S]*?)\}\}/g;
  for (const match of template.matchAll(pattern)) {
    const literal = template.slice(offset, match.index);
    if (literal.includes('{{') || literal.includes('}}')) throw new Error('malformed template placeholder');
    parts.push({literal});
    const spec = match[1].trim().match(/^(secret:\/\/[^\s/|{}]+\/[^\s/|{}]+)(?:\s*\|\s*(raw|json|uri))?$/);
    if (!spec) throw new Error('invalid template placeholder: expected secret://id/field | raw, json or uri');
    parts.push({ref:spec[1],format:(spec[2] ?? 'raw') as 'raw'|'json'|'uri'});
    offset = match.index! + match[0].length;
  }
  const tail = template.slice(offset);
  if (tail.includes('{{') || tail.includes('}}')) throw new Error('malformed template placeholder');
  parts.push({literal:tail});
  if (parts.length > 513) throw new Error('template exceeds 256 placeholders');
  return parts;
}
export async function renderTemplate(parts: TemplatePart[], draw: (ref: string) => Promise<string>): Promise<{text:string; sensitive:string[]}> {
  const cache = new Map<string,string>();
  const sensitive = new Set<string>();
  let text = '';
  for (const part of parts) {
    if ('literal' in part) { text += part.literal; continue; }
    if (!cache.has(part.ref)) cache.set(part.ref, await draw(part.ref));
    const value = cache.get(part.ref)!;
    const formatted = part.format === 'json' ? JSON.stringify(value) : part.format === 'uri' ? encodeURIComponent(value) : value;
    sensitive.add(value); sensitive.add(formatted); text += formatted;
    if (Buffer.byteLength(text) > 4 * 1024 * 1024) throw new Error('rendered template exceeds 4 MiB');
  }
  if (Buffer.byteLength(text) > 4 * 1024 * 1024) throw new Error('rendered template exceeds 4 MiB');
  return {text,sensitive:[...sensitive]};
}
