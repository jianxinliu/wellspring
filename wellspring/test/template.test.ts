import {test,expect} from 'bun:test';
import {parseTemplate,renderTemplate} from '../src/core/template.ts';
test('templates encode JSON/URI and draw repeated refs once',async()=>{
  const value='a"b\n/?';let calls=0;
  const rendered=await renderTemplate(parseTemplate('{"password":{{secret://cred:db/password | json}},"url":"{{secret://cred:db/password | uri}}"}'),async()=>{calls++;return value;});
  expect(JSON.parse(rendered.text)).toEqual({password:value,url:encodeURIComponent(value)});
  expect(calls).toBe(1);expect(rendered.sensitive).toContain(JSON.stringify(value));
});
test('templates reject expressions, unknown formats and malformed placeholders before draws',()=>{
  for(const text of ['{{process.env.KEY}}','{{secret://cred:db/password | shell}}','{{secret://cred:db/password','x}}','{{secret://cred:db/password/extra}}'])expect(()=>parseTemplate(text)).toThrow();
  expect(()=>parseTemplate('x'.repeat(1024*1024+1))).toThrow();
  expect(()=>parseTemplate('{{secret://cred:db/password}}'.repeat(257))).toThrow();
});
