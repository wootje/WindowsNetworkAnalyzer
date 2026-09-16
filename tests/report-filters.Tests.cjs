'use strict';
// Pure Node tests. No network, browser or Windows access is required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const filters = require('../report-filters.js');
let count = 0;
function test(label, action) { action(); count++; console.log('PASS ' + label); }
const base = {
  processName: 'svchost.exe', processId: 1234,
  processPath: 'C:\\Windows\\System32\\svchost.exe',
  services: ['Dnscache'], serviceDetails: [{name:'Dnscache', displayName:'DNS Client',description:'Resolves and caches domain names'}],
  localAddress: '192.168.1.10', remoteAddress: '8.8.8.8', localPort: 53123, remotePort: 443,
  dnsNames: ['Example.COM'], ptrNames: ['dns.google'],
  ipRegistration: {organization:'Example Network Company',name:'GOOGLE',country:'US',status:'Success'},
  localIpRegistration:{organization:'LOCAL TEST ONLY',name:'LOCAL',country:'ZZ',status:'LocalOnly'},
  domainRegistrations:[{organization:'Domain Registry Customer',country:'NL',status:'NotFound'}],
  company:'Microsoft Corporation', signer:'Microsoft Windows',signatureStatus:'Valid',
  direction:'Outbound',metadataStatus:'Complete',sha256:'ABCDEF12345', observations:7,
  firstSeen:'2026-09-15T10:00:00.0000000Z',lastSeen:'2026-09-15T10:10:00Z'
};
function yes(state, row=base) { assert.equal(filters.matches(row,state),true,JSON.stringify(state)); }
function no(state, row=base) { assert.equal(filters.matches(row,state),false,JSON.stringify(state)); }
function invalid(state) { assert.ok(filters.validate(state).length); no(state); }
test('empty state and global API are usable',()=>{yes({});yes(undefined);assert.equal(globalThis.NetworkReportFilters,filters);});
test('browser script exposes API without CommonJS',()=>{
  const context={};vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../report-filters.js'),'utf8'),context);
  assert.equal(typeof context.NetworkReportFilters.compile,'function');assert.equal(context.NetworkReportFilters.matches(base,{}),true);
});
test('process name and path searches ignore case',()=>{yes({processName:'SVC',processPath:'WINDOWS\\SYSTEM32'});no({processName:'chrome'});});
test('PID supports comma alternatives and ranges',()=>{yes({processId:'10,1000-1300,9999'});no({processId:'0,2-20'});});
test('missing PID never becomes zero',()=>{no({processId:'0'},{...base,processId:null});no({processId:'0'},{...base,processId:''});yes({processId:'0'},{...base,processId:0});});
test('ports support inclusive ranges and zero',()=>{yes({localPort:'50000-60000',remotePort:'53,80,443'});yes({remotePort:'0'},{...base,remotePort:0});no({remotePort:'0'},{...base,remotePort:null});});
test('bad PID and port ranges fail closed',()=>{for(const state of [{processId:'-1'},{processId:'2147483648'},{localPort:'65536'},{remotePort:'443-80'},{remotePort:'80,,443'},{remotePort:'1.5'},{processId:'0x10'},{remotePort:'1-2-3'}])invalid(state);});
test('service filter covers names, display names and descriptions',()=>{yes({service:'dnscache'});yes({service:'DNS CLIENT'});yes({service:'caches domain'});no({service:'Windows Update'});});
test('IPv4 exact matching is not substring matching',()=>{yes({remoteIp:'8.8.8.8'});no({remoteIp:'8.8.8.80'});invalid({remoteIp:'8.8'});});
test('IPv4 CIDR supports boundaries and alternatives',()=>{yes({remoteIp:'1.1.1.1,8.8.8.0/24'});yes({localIp:'192.168.1.0/24'});no({remoteIp:'8.8.9.0/24'});yes({remoteIp:'8.8.8.8/32'});no({remoteIp:'8.8.8.9/32'});yes({remoteIp:'0.0.0.0/0'});});
test('IPv4 non-octet CIDR boundaries are correct',()=>{yes({remoteIp:'8.8.8.8/31'},{...base,remoteAddress:'8.8.8.9'});no({remoteIp:'8.8.8.8/31'},{...base,remoteAddress:'8.8.8.10'});});
test('invalid IP and CIDR input cannot disable a filter',()=>{for(const remoteIp of ['256.1.1.1','8.8.8.8/33','8.8.8.8/-1','8.8.8.8/','8.8.8.8/24/1','::gg','2001::1::2','::1/129','1::2::3','8.8.8.8,','example.com'])invalid({remoteIp});});
test('IPv6 compressed and expanded forms match',()=>{
 const r={...base,remoteAddress:'2001:db8::abcd'};yes({remoteIp:'2001:0db8:0000:0:0:0:0:abcd'},r);yes({remoteIp:'2001:db8::/32'},r);no({remoteIp:'2001:db9::/32'},r);
});
test('IPv6 non-byte CIDR boundaries are correct',()=>{const r={...base,remoteAddress:'2001:db8::3'};yes({remoteIp:'2001:db8::2/127'},r);no({remoteIp:'2001:db8::/127'},r);});
test('unscoped IPv6 filters accept zones while explicit zones restrict interfaces',()=>{const r={...base,remoteAddress:'fe80::1%12'};yes({remoteIp:'fe80::1'},r);yes({remoteIp:'[fe80::1]'},r);yes({remoteIp:'fe80::/64'},r);yes({remoteIp:'fe80::1%12'},r);no({remoteIp:'fe80::1%7'},r);yes({remoteIp:'fe80::%12/64'},r);no({remoteIp:'fe80::%7/64'},r);no({remoteIp:'fe80::1%12'},{...base,remoteAddress:'fe80::1'});});
test('embedded IPv4 tails retain IPv6 family',()=>{const r={...base,remoteAddress:'::ffff:192.0.2.1'};yes({remoteIp:'::ffff:c000:201'},r);yes({remoteIp:'::ffff:0:0/96'},r);no({remoteIp:'192.0.2.0/24'},r);yes({ipFamily:'IPv6'},r);});
test('family uses peer, then local when peer is missing',()=>{yes({ipFamily:'IPv4'});yes({ipFamily:'IPv6'},{...base,remoteAddress:'2001:db8::1'});yes({ipFamily:'IPv4'},{...base,remoteAddress:'::'});yes({ipFamily:'Unknown'},{...base,remoteAddress:'',localAddress:''});invalid({ipFamily:'something'});});
test('DNS and PTR are distinct filters',()=>{yes({dnsName:'EXAMPLE',ptrName:'GOOGLE'});no({dnsName:'google'});no({ptrName:'example'});});
test('DNS presence does not infer DNS from PTR',()=>{yes({dnsPresence:'recorded'});yes({dnsPresence:'missing'},{...base,dnsNames:[]});no({dnsPresence:'recorded'},{...base,dnsNames:[],ptrNames:['dns.google']});invalid({dnsPresence:'maybe'});});
test('remote missing includes zero and wildcard endpoints',()=>{for(const address of ['',null,'*','-','0.0.0.0','::','0:0:0:0:0:0:0:0']){yes({remotePresence:'missing'},{...base,remoteAddress:address});no({remotePresence:'recorded'},{...base,remoteAddress:address});}yes({remotePresence:'recorded'});});
test('organization searches remote IP and domain registration, not local IP',()=>{yes({organization:'NETWORK COMPANY'});yes({organization:'GOOGLE'});yes({organization:'registry customer'});no({organization:'LOCAL TEST ONLY'});});
test('registration country codes support comma OR and ignore case',()=>{yes({country:'us'});yes({country:'DE,NL'});no({country:'ZZ'});invalid({country:'United States'});});
test('RDAP status searches remote and domain results',()=>{yes({rdapStatus:'success'});yes({rdapStatus:'NotFound'});no({rdapStatus:'LocalOnly'});yes({rdapStatus:'Not recorded'},{...base,ipRegistration:null,domainRegistrations:[]});});
test('signature, signer, company and hash filters are independent',()=>{yes({signature:'valid',signer:'WINDOWS',company:'MICROSOFT',hash:'abcdef'});no({signature:'Invalid'});no({hash:'deadbeef'});});
test('metadata and direction selectors match exact values',()=>{yes({metadataStatus:'complete',direction:'outbound'});no({direction:'inbound'});no({metadataStatus:'TimedOut'});});
test('unknown direction includes snapshot and local endpoint states',()=>{for(const direction of ['Unknown (snapshot)','Unknown (local endpoint)','Unknown',''])yes({direction:'Unknown'},{...base,direction});no({direction:'Unknown'});});
test('observation bounds are inclusive and non-negative',()=>{yes({minObservations:'7',maxObservations:'7'});no({minObservations:'8'});no({maxObservations:'6'});yes({minObservations:'0'},{...base,observations:0});no({minObservations:'0'},{...base,observations:null});});
test('invalid observation bounds fail closed',()=>{for(const state of [{minObservations:'8',maxObservations:'7'},{minObservations:'-1'},{maxObservations:'2.5'},{minObservations:'Infinity'},{maxObservations:'9007199254740992'}])invalid(state);});
test('time filtering uses inclusive interval overlap',()=>{yes({timeFrom:'2026-09-15T10:10:00Z'});yes({timeTo:'2026-09-15T10:00:00Z'});yes({timeFrom:'2026-09-15T10:05',timeTo:'2026-09-15T10:06'});no({timeFrom:'2026-09-15T10:10:01Z'});no({timeTo:'2026-09-15T09:59:59Z'});});
test('time offsets are normalized to UTC',()=>{yes({timeFrom:'2026-09-15T12:05:00+02:00',timeTo:'2026-09-15T12:06:00+02:00'});no({timeFrom:'2026-09-15T12:05:00Z'});});
test('one available row timestamp is usable; neither cannot match',()=>{yes({timeFrom:'2026-09-15T10:00Z'},{...base,lastSeen:null});no({timeFrom:'2026-09-15T10:00Z'},{...base,lastSeen:null,firstSeen:null});});
test('invalid dates and reversed time ranges fail closed',()=>{for(const state of [{timeFrom:'2026-02-30T10:00Z'},{timeFrom:'2026-09-15T25:00Z'},{timeFrom:'tomorrow'},{timeFrom:'2026-09-15T10:00+99:00'},{timeFrom:'2026-09-15T11:00Z',timeTo:'2026-09-15T10:00Z'}])invalid(state);});
test('all active fields combine with AND',()=>{yes({processName:'svchost',remoteIp:'8.8.8.0/24',remotePort:'443',country:'US',minObservations:'7',dnsPresence:'recorded'});no({processName:'svchost',remoteIp:'1.1.1.0/24',remotePort:'443'});});
test('empty and any selectors do not constrain data',()=>{yes({signature:'any',direction:'any',ipFamily:'any',metadataStatus:'any',rdapStatus:'any',dnsPresence:'any',remotePresence:'any'});});
test('unsupported active values and excessive input fail closed',()=>{invalid({processName:{bad:'input'}});invalid({processName:'x'.repeat(2049)});invalid({remotePort:Array(129).fill('443').join(',')});assert.ok(filters.validate([]).length);});
test('literal text filters cannot execute or become regular expressions',()=>{no({processName:'.*'});no({processName:'(a+)+$'});no({service:'<script>alert(1)</script>'});yes({processName:'.*'},{...base,processName:'literal.*name'});});
test('compiled filter is independent of later state mutations',()=>{const state={remotePort:'443'};const compiled=filters.compile(state);state.remotePort='80';assert.equal(compiled.matches(base),true);assert.equal(compiled.matches({...base,remotePort:80}),false);});
test('filtering does not mutate rows or their arrays',()=>{const row=JSON.parse(JSON.stringify(base));const before=JSON.stringify(row);yes({service:'DNS',organization:'network',remoteIp:'8.8.8.0/24'},row);assert.equal(JSON.stringify(row),before);});
test('compile once supports 10000 records and repeated addresses',()=>{
 const compiled=filters.compile({processName:'svchost',remoteIp:'8.8.8.0/24',remotePort:'443',timeFrom:'2026-09-15T10:00Z'});
 let matches=0;for(let i=0;i<10000;i++)if(compiled.matches({...base,remotePort:i%2?443:80}))matches++;
 assert.equal(matches,5000);assert.deepEqual(compiled.errors,[]);
});
console.log('All '+count+' advanced-filter tests passed.');
