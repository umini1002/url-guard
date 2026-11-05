import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
const read=file=>readFileSync(new URL('../'+file,import.meta.url),'utf8');
const configured=read('_site/config.js');
test('Pages build contains only frontend and uses HTTPS API',()=>{
  const context={};vm.createContext(context);vm.runInContext(configured,context);
  assert.ok(context.URL_GUARD_CONFIG.apiBase.startsWith('https://'));
  const html=read('_site/index.html');
  assert.ok(html.includes('src="config.js"'));
  assert.ok(!html.includes('id="api"'));
  assert.ok(read('_site/app.js').includes("fetch('samples.json')"));
});
test('Project-path samples and remote Python request work without visitor settings',async()=>{
  const elements=new Map();
  const node=()=>({hidden:true,style:{},value:'',children:[],append(...items){this.children.push(...items)},replaceChildren(){this.children=[]},setAttribute(){},scrollIntoView(){},focus(){}});
  const buttons=['safe','suspicious','phishing'].map(type=>({...node(),dataset:{sample:type}}));
  const samples=JSON.parse(read('_site/samples.json'));let requests=[];
  const context={document:{getElementById(id){if(!elements.has(id))elements.set(id,node());return elements.get(id)},querySelectorAll(){return buttons},createElement:node},AbortSignal,Date,
    fetch:async(url,options)=>{requests.push({url,options});return url==='samples.json'?{ok:true,json:async()=>samples}:{ok:true,headers:{get(){return 'application/json'}},json:async()=>samples.safe};}};
  vm.createContext(context);vm.runInContext(configured,context);vm.runInContext(read('_site/app.js'),context);
  await buttons[1].onclick();assert.equal(requests[0].url,'samples.json');
  assert.equal(elements.get('sample-notice').hidden,false);
  context.document.getElementById('url').value='https://example.com';
  await elements.get('form').onsubmit({preventDefault(){}});
  assert.equal(requests[1].url,context.URL_GUARD_CONFIG.apiBase+'/api/analyze');
  assert.equal(JSON.parse(requests[1].options.body).url,'https://example.com');
  assert.equal(elements.get('sample-notice').hidden,true);
});
