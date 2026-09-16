/* Offline UI checks using a deterministic DOM test double. No external dependencies.
   These tests exercise scripts and interactions, not a browser's CSS layout engine. */
'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const template=fs.readFileSync(path.join(__dirname,'..','report-template.html'),'utf8');
const scripts=[...template.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)];
const source=scripts[scripts.length-1][1];new vm.Script(source);
class Element{
 constructor(tag='div'){this.tagName=tag;this.children=[];this.attributes={};this.style={};this.events={};this.value='';this.checked=true;this.hidden=false;this.dataset={};this._text='';this.className='';this.classList={add:x=>this.className+=' '+x,contains:x=>this.className.split(/\s+/).includes(x),toggle:x=>{this.className=this.className.split(/\s+/).includes(x)?this.className.split(/\s+/).filter(v=>v!==x).join(' '):this.className+' '+x;}}}
 set textContent(v){this.children=[];this._text=String(v)}get textContent(){return this._text+this.children.map(c=>c.textContent).join('')}
 appendChild(c){c.parentElement=this;this.children.push(c);return c}replaceChildren(...c){this.children=[];this._text='';c.forEach(v=>this.appendChild(v))}
 addEventListener(e,f){this.events[e]=f}setAttribute(k,v){this.attributes[k]=String(v)}getAttribute(k){return this.attributes[k]}
 querySelector(selector){const pred=selector==='.sort'?e=>e.className==='sort':e=>e.tagName===selector;for(const ch of this.children){if(pred(ch))return ch;const f=ch.querySelector(selector);if(f)return f;}return null}
 click(){if(this.events.click)return this.events.click({target:this,clientX:10,clientY:10})}focus(){this.focused=true}showModal(){this.open=true}close(){this.open=false}remove(){}get lastChild(){return this.children[this.children.length-1]}getBoundingClientRect(){return {left:0,top:0,right:100,bottom:100}}
}
function descendants(e){return e.children.flatMap(x=>[x,...descendants(x)])}
function mount(data){
 const ids={};[...template.matchAll(/\bid="([^\"]+)"/g)].forEach(m=>ids[m[1]]=new Element());ids['page-size'].value='50';['quic','public'].forEach(n=>ids['chip-'+n].setAttribute('aria-pressed','false'));
 const ths=['app','protocol','remote','explanation','dns','owner','state','source','lastSeen'].map(key=>{const th=new Element('th');th.dataset.key=key;const b=th.appendChild(new Element('button'));const span=b.appendChild(new Element('span'));span.className='sort';return th});ids['report-data'].textContent=JSON.stringify(data);
 let exported,downloadCount=0;
 const doc={getElementById:id=>{assert(ids[id],'Unknown UI element '+id);return ids[id]},createElement:t=>new Element(t),createTextNode:t=>{const e=new Element('#text');e.textContent=t;return e},createDocumentFragment:()=>new Element('#fragment'),querySelectorAll:s=>s==='th[data-key]'?ths:s==='th[data-key] button'?ths.map(t=>t.children[0]):[],documentElement:new Element('html'),body:new Element('body')};
 const context={console,document:doc,window:{matchMedia:()=>({matches:false})},navigator:{},Intl,Date,JSON,Number,String,Array,Object,Set,Map,URL:class extends URL{static createObjectURL(b){exported=b;downloadCount++;return 'blob:test'}static revokeObjectURL(){}},Blob,setTimeout:f=>{f();return 1},clearTimeout:()=>{}};
 vm.runInNewContext(fs.readFileSync(path.join(__dirname,'..','report-filters.js'),'utf8'),context);
 vm.runInNewContext(source,context,{timeout:15000});
 return {ids,ths,context,exported:()=>exported,downloadCount:()=>downloadCount,change:(id,value)=>{ids[id].value=value;ids[id].events.change()},input:(id,value)=>{ids[id].value=value;ids[id].events.input()},rows:id=>ids[id||'rows'].children[0].children,clickFirstRecord:()=>ids.rows.children[0].children[0].children[0].children[0].click()};
}
const records=Array.from({length:10000},(_,i)=>({id:'c'+String(i).padStart(6,'0'),protocol:i%3===0?'UDP':'TCP',localAddress:'10.0.0.2',localPort:40000+i,remoteAddress:i%9===0?'':i%5===0?'10.0.0.50':'198.51.100.'+(i%255),remotePort:i%2===0?443:80,processId:100+i%120,processName:'app'+i%120+'.exe',processPath:'C:\\Applications\\App'+i%120+'\\app.exe',application:'Application '+i%120,dnsNames:['example.test'],dnsEvidence:'DNS cache candidate only',state:i%7===0?'Listen':'Established',source:i%2===0?'TcpSnapshot':'WFP5156',ipScope:i%9===0?'Unknown':i%5===0?'Private':'Public',firstSeen:'2026-09-15T10:00:00Z',lastSeen:'2026-09-15T10:02:00Z',allowed:i%3===0?true:i%3===1?false:'Unknown',direction:i%2===0?'Unknown (snapshot)':'Outbound',signatureStatus:i%5===0?'NotSigned':'Valid',sha256:'abcd',metadataCollectedUtc:'2026-09-15T10:03:00Z',ipRegistration:{name:'Example registry fixture',country:'ZZ',sourceUrl:'https://rdap.example.test/ip/198.51.100.1'}}));
records.forEach((r,i)=>{
 r.attributionStatus=i%4===0?'MatchedLiveProcess':'WfpEventPathOnly';
 r.processEvidence='Fixture process lifetime evidence';
 r.serviceEvidence='Fixture service association collected from the live PID';
 r.serviceDetails=i%4===0?[{name:'FixtureService'+i,displayName:'Fixture Windows Service '+i,description:'Fixture service description '+i,state:'Running',startMode:'Auto'}]:[];
 r.explanation={category:i%4===0?'DNS':i%2===0?'Web traffic':'Unknown',summary:'Fixture explanation '+i,processRole:i%4===0?'Windows service host candidate':'Application process candidate',purpose:'Possible network feature; exact content not collected.',confidence:i%2===0?'Likely':'Unknown',evidence:['Observed fixture endpoint'],limitations:['Fixture names do not establish trust'],suggestedCheck:'Compare the feature with a deliberate action.',serviceContext:'Several services can share one host process.',necessity:'Whether this traffic is needed depends on the features in use.'};
});
records[0].explanation.summary='=EXPLANATION_FORMULA';records[0].explanation.confidence='Observed';records[0].explanation.evidence=['<img src=x onerror=alert(1)> EXPLANATION_EVIDENCE'];records[0].explanation.limitations=['<svg onload=alert(1)> EXPLANATION_LIMIT'];records[0].explanation.suggestedCheck='<script>alert(1)</script> NEXT_CHECK';records[0].explanation.processRole='<img src=x onerror=alert(1)> PROCESS_ROLE';
records[0].serviceDetails=[{name:'Dnscache',displayName:'DNS Client DisplayNameMarker',description:'<img src=x onerror=alert(1)> ServiceDescriptionMarker',state:'Running',startMode:'Auto'}];
records[2].explanation.summary='<svg onload=alert(1)> EXPLANATION_SUMMARY';records[4].direction='Inbound';
records[0].application='=FORMULA_TEST';records[0].dnsNames=['<img src=x onerror=alert(1)>'];records[0].ipRegistration.sourceUrl='javascript:alert(1)';records[0].ipRegistration.rawFile='../secret.json';records[0].localIpRegistration={name:'LOCAL-TEST-NETWORK',query:'10.0.0.2',organization:'Local Organization Marker',country:'NL',sourceUrl:'https://rdap.example.test/ip/10.0.0.2'};records[0].ipRegistration.registrationEvents=[{action:'registration',date:'2020-01-01T00:00:00Z'}];records[0].ipRegistration.entities=[{name:'Example Entity'}];records[0].metadataStatus='Complete';records[0].fileSize=1024;

records.forEach((r,i)=>{r.observations=1+i%10;r.ptrNames=['peer.example.test'];r.company='Example Company';});
const data={meta:{computer:'TEST-PC',version:'3.0.0',phase:'Complete',started:'2026-09-15T10:00:00Z',finished:'2026-09-15T10:02:00Z',warnings:['<script>alert(1)</script>']},connections:records};
async function main(){
 let checks=0;const test=(label,fn)=>{try{fn();checks++;}catch(e){e.message=label+': '+e.message;throw e}};
 const m=mount(data),{ids,ths}=m;
 test('original single-table design retained',()=>{assert(!template.includes('view-overview'));assert(!template.includes('tab-findings'));assert(template.includes('Which process is connecting?'))});
 test('English statistics and paginated 10k records',()=>{assert.equal(ids['stat-rows'].textContent,'10,000');assert.equal(m.rows().length,50)});
 test('process and PID are primary row identity',()=>{assert.equal(m.rows()[0].children[0].children[0].textContent,'app0.exe · PID 100');assert(m.rows()[0].children[0].textContent.includes('=FORMULA_TEST'));assert(m.rows()[0].children[0].textContent.includes('Matched live process'));assert(m.rows()[0].children[0].textContent.includes('DNS Client DisplayNameMarker'))});
 test('each row has an explanation column',()=>{assert.equal(m.rows()[0].children.length,9);assert(m.rows()[0].children[3].textContent.includes('=EXPLANATION_FORMULA'));assert(m.rows()[0].children[3].textContent.includes('Purpose: Observed'))});
 test('collection warnings render as literal text',()=>{assert(!ids.warnings.hidden);assert(ids['warning-list'].textContent.includes('<script>'));assert(!descendants(ids['warning-list']).some(x=>x.tagName==='script'))});
 test('display timestamps use UTC',()=>{assert(m.rows()[0].children[8].textContent.includes('2026-09-15 10:02:00 UTC'));assert(ids['time-zone'].textContent.includes('UTC'))});
 ids['chip-quic'].click();test('original UDP 443 filter',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>r.protocol==='UDP'&&r.remotePort===443).length.toLocaleString('en-US')));
 ids.reset.click();ids['chip-public'].click();test('original public scope filter',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>r.ipScope==='Public').length.toLocaleString('en-US')));
 ids.reset.click();m.change('filter-category','DNS');test('purpose category filter',()=>assert.equal(ids['stat-rows'].textContent,'2,500'));
 ids.reset.click();m.change('filter-confidence','Observed');test('purpose confidence filter',()=>assert.equal(ids['stat-rows'].textContent,'1'));
 ids.reset.click();m.change('filter-attribution','Matched live process');test('attribution filter',()=>assert.equal(ids['stat-rows'].textContent,'2,500'));
 ids.reset.click();m.input('search','ServiceDescriptionMarker');test('search service descriptions',()=>assert.equal(ids['stat-rows'].textContent,'1'));
 ids.reset.click();m.input('search','EXPLANATION_EVIDENCE');test('search explanation evidence',()=>assert.equal(ids['stat-rows'].textContent,'1'));
 ids.reset.click();m.input('search','FORMULA_TEST');m.clickFirstRecord();
 test('modal process and full explanation',()=>{assert(ids.detail.open);assert.equal(ids['detail-title'].textContent,'app0.exe · PID 100');assert(ids['detail-body'].children[0].textContent.includes('What this connection may be for'));assert(ids['detail-body'].textContent.includes('It is not a trust rating'));assert(ids['detail-body'].textContent.includes('NEXT_CHECK'))});
 test('shared service context and evidence',()=>{assert(ids['detail-body'].textContent.includes('ServiceDescriptionMarker'));assert(ids['detail-body'].textContent.includes('Fixture process lifetime evidence'));assert(ids['detail-body'].textContent.includes('Several services can share one host process.'))});
 test('full file and registry evidence',()=>{assert(ids['detail-body'].textContent.includes('SHA-256'));assert(ids['detail-body'].textContent.includes('Registration events'));assert(ids['detail-body'].textContent.includes('Local Organization Marker'));assert(ids['detail-body'].textContent.includes('Metadata result'))});
 test('unknown direction does not invent outbound traffic',()=>{assert(ids['detail-subtitle'].textContent.includes(' | Remote '));assert(!ids['detail-subtitle'].textContent.includes(' → '))});
 test('details reject executable HTML and unsafe links',()=>{assert(ids['detail-body'].textContent.includes('<img src=x'));assert(!descendants(ids['detail-body']).some(e=>['img','script','svg'].includes(e.tagName)));assert(!descendants(ids['detail-body']).some(e=>e.href==='javascript:alert(1)'||e.href==='../secret.json'))});
 ids.export.click();const csv=await m.exported().text();
 test('CSV retains local and remote registration fields',()=>{['Local IP organization','Local IP registered name','Local IP registration country','Local IP registration status','Local IP RDAP source','Local Organization Marker','IP organization','Domain registrations JSON'].forEach(v=>assert(csv.includes(v)))});
 test('CSV includes process, explanation and metadata evidence',()=>{['Attribution status','Process evidence','Service details JSON','Service evidence','Purpose category','Purpose confidence','Explanation','Process role','Possible purpose','Necessity','Supporting evidence','Explanation limitations','Suggested next check','Service context','SHA-256'].forEach(v=>assert(csv.includes(v)))});
 test('CSV formula cells neutralized',()=>{assert(csv.includes('"\'=FORMULA_TEST"'));assert(csv.includes('"\'=EXPLANATION_FORMULA"'))});
 ids['close-detail'].click();test('modal closes',()=>assert(!ids.detail.open));
 ids.reset.click();m.input('search','c000004');m.clickFirstRecord();test('inbound direction points remote to local',()=>assert(ids['detail-subtitle'].textContent.includes('Remote 198.51.100.4:443 → Local 10.0.0.2:40004')));ids['close-detail'].click();
 ids.reset.click();m.input('search','c000001');m.rows()[0].children[3].children[0].click();test('explanation opens modal and outbound route',()=>{assert(ids.detail.open);assert(ids['detail-subtitle'].textContent.includes('Local 10.0.0.2:40001 → Remote 198.51.100.1:80'))});ids['close-detail'].click();
 ids.reset.click();m.change('filter-allowed','Blocked');test('audit decision filtering retained',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>r.allowed===false).length.toLocaleString('en-US')));
 ids.reset.click();m.change('page-size','250');test('page size retained',()=>assert.equal(m.rows().length,250));ids.next.click();test('pagination retained',()=>assert.equal(ids['page-status'].textContent,'2 / 40'));
 ths[0].children[0].click();test('sorting retained',()=>assert.equal(ths[0].getAttribute('aria-sort'),'ascending'));ths[0].children[0].click();test('reverse sorting retained',()=>assert.equal(ths[0].getAttribute('aria-sort'),'descending'));
 ids['show-listening'].checked=false;ids['show-listening'].events.change();test('listener exclusion retained',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>r.state!=='Listen').length.toLocaleString('en-US')));
 const advanced=['processName','processId','processPath','service','localIp','remoteIp','localPort','remotePort','dnsName','ptrName','organization','country','signature','signer','direction','ipFamily','metadataStatus','rdapStatus','minObservations','maxObservations','timeFrom','timeTo','dnsPresence','remotePresence','hash','company'];
 test('all 26 advanced fields wired',()=>advanced.forEach(k=>{assert(ids['adv-'+k]);assert(ids['adv-'+k].events.input);assert(ids['adv-'+k].events.change)}));
 ids.reset.click();m.input('adv-processName','app0.exe');test('advanced process-name field',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>r.processName==='app0.exe').length.toLocaleString('en-US')));
 ids.reset.click();m.input('adv-processId','100-102');test('advanced PID ranges',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>r.processId>=100&&r.processId<=102).length.toLocaleString('en-US')));
 ids.reset.click();m.input('adv-service','DescriptionMarker');test('advanced service description',()=>assert.equal(ids['stat-rows'].textContent,'1'));
 ids.reset.click();m.input('adv-remoteIp','198.51.100.0/24');m.input('adv-remotePort','443');test('advanced network and port AND matching',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>r.remoteAddress.startsWith('198.51.100.')&&r.remotePort===443).length.toLocaleString('en-US')));
 test('active filter counter',()=>assert.equal(ids['active-filters'].textContent,'2 active filters'));
 ids.reset.click();test('reset clears advanced and basic controls',()=>{advanced.forEach(k=>assert.equal(ids['adv-'+k].value,''));assert.equal(ids['active-filters'].textContent,'No active filters');assert.equal(ids['stat-rows'].textContent,'10,000')});
 m.input('adv-remotePort','70000');test('invalid filters show errors and no matches',()=>{assert(!ids['filter-errors'].hidden);assert.equal(ids['stat-rows'].textContent,'0');assert(ids['filter-errors'].textContent.includes('65535'))});
 ids.reset.click();test('reset clears filter errors',()=>assert(ids['filter-errors'].hidden));
 m.change('adv-signature','NotSigned');test('dynamic signature selection',()=>assert.equal(ids['stat-rows'].textContent,'2,000'));
 ids.reset.click();m.change('adv-direction','Unknown');test('group unknown direction variants',()=>assert.equal(ids['stat-rows'].textContent,'4,999'));
 ids.reset.click();m.change('adv-dnsPresence','missing');test('missing DNS',()=>assert.equal(ids['stat-rows'].textContent,'0'));
 ids.reset.click();m.change('adv-remotePresence','missing');test('missing UDP/TCP remote endpoints',()=>assert.equal(ids['stat-rows'].textContent,records.filter(r=>!r.remoteAddress).length.toLocaleString('en-US')));
 ids.reset.click();m.input('adv-timeFrom','2026-09-15T10:01');m.input('adv-timeTo','2026-09-15T10:03');test('UTC overlap filter',()=>assert.equal(ids['stat-rows'].textContent,'10,000'));
 m.input('adv-timeFrom','2026-09-15T10:04');test('inverted time range fails closed',()=>{assert.equal(ids['stat-rows'].textContent,'0');assert(!ids['filter-errors'].hidden)});
 ids.reset.click();m.input('adv-minObservations','8');test('minimum sightings filter',()=>assert.equal(ids['stat-rows'].textContent,'3,000'));
 ids.reset.click();m.input('adv-country','NL');test('local registration cannot satisfy remote country filter',()=>assert.equal(ids['stat-rows'].textContent,'0'));
 ids.reset.click();const before=ids.theme.textContent;ids.theme.click();test('theme toggle retained',()=>assert.notEqual(ids.theme.textContent,before));
 const zero=mount({meta:{},connections:[]});test('empty report',()=>{assert.equal(zero.ids['stat-rows'].textContent,'0');assert(zero.ids.rows.textContent.includes('No connections recorded'))});
 const legacy={...records[1]};['explanation','serviceDetails','serviceEvidence','attributionStatus','processEvidence'].forEach(k=>delete legacy[k]);const old=mount({meta:{},connections:[legacy]});test('partial rows retain unknown fields instead of guesses',()=>{assert(old.rows()[0].children[3].textContent.includes('purpose of this connection was not recorded'));assert(old.rows()[0].children[0].textContent.includes('Attribution not recorded'));old.clickFirstRecord();assert(old.ids['detail-body'].textContent.includes('No hosted Windows services were recorded'))});
 const noSize=mount({meta:{},connections:[{...records[1],fileSize:'',hashStatus:'NotCollected',ptrStatus:'Skipped'}]});noSize.clickFirstRecord();test('missing file size remains unknown and diagnostic details visible',()=>{assert(!noSize.ids['detail-body'].textContent.includes('0 bytes'));assert(noSize.ids['detail-body'].textContent.includes('Hash result'));assert(noSize.ids['detail-body'].textContent.includes('PTR lookup result'));assert(!noSize.ids['detail-body'].textContent.includes('collection formatTime'))});
 const invalid=mount({meta:{}});test('invalid data fails clearly',()=>assert(invalid.ids.error.textContent.includes('could not be read')));
 test('offline English report with preserved responsive layout',()=>{assert(template.includes('lang="en"'));assert(!/portmaster/i.test(template));assert(!/\bfetch\s*\(|XMLHttpRequest|new WebSocket/.test(source));assert(template.includes("connect-src 'none'"));assert(template.includes('@media(max-width:650px)'));assert(!/lang="nl"|nl-NL|Toepassing|Verbindingsdetails|Geen gegevens/.test(template))});
 console.log(JSON.stringify({passed:true,checks,rows:10000,layout:'DOM test double; browser layout not tested',features:['original single-table design','English interface','process-first identity','service details','per-connection explanations','original filters and CSV retained','26 advanced filter fields','AND filters and reset','validation errors','consistent UTC times','safe text and links','CSV formula protection','empty and partial records']},null,2));
}
main().catch(e=>{console.error(e);process.exitCode=1});
