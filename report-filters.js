/* Windows Network Analyzer: offline, dependency-free advanced filters.
 * Every active field is combined with AND. Lists within numeric/IP/country
 * fields use OR. No regular expressions supplied by users are evaluated.
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.NetworkReportFilters = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  var MAX_LENGTH = 2048, MAX_ENTRIES = 128;
  var fields = ['processName','processId','processPath','service','localIp','remoteIp',
    'localPort','remotePort','dnsName','ptrName','organization','country','signature',
    'signer','direction','ipFamily','metadataStatus','rdapStatus','minObservations',
    'maxObservations','timeFrom','timeTo','dnsPresence','remotePresence','hash','company'];
  function text(v) { return v === undefined || v === null ? '' : String(v); }
  function lower(v) { return text(v).toLowerCase(); }
  function values(v) { return Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]; }
  function names(v) { return values(v).map(function (x) {
    return x && typeof x === 'object' ? text(x.name || x.domain || x.hostname) : text(x);
  }).filter(function (x) { return x.trim() !== ''; }); }
  function missingRemote(v) {
    var s = text(v).trim();
    if (!s || s === '*' || s === '-') return true;
    var ip = parseIp(s);
    return !!ip && ip.bytes.every(function (b) { return b === 0; });
  }
  function parseV4(s) {
    var p = s.split('.');
    if (p.length !== 4 || p.some(function (x) { return !/^\d{1,3}$/.test(x) || Number(x) > 255; })) return null;
    return p.map(Number);
  }
  function parseIp(value) {
    var s = text(value).trim(), zone = '', bytes, colon, halves, left, right, words;
    if (!s || s.length > 128) return null;
    if (s.charAt(0) === '[' && s.charAt(s.length - 1) === ']') s = s.slice(1, -1);
    if (s.indexOf('%') !== -1) {
      if (!/^[^%]+%[A-Za-z0-9_.-]+$/.test(s) || s.indexOf(':') === -1) return null;
      zone = s.split('%')[1];
      s = s.split('%')[0]; // Retain the interface selector separately from address bits.
    }
    if (s.indexOf(':') === -1) {
      bytes = parseV4(s); return bytes ? {family: 4, bytes: bytes} : null;
    }
    if (s.indexOf('.') !== -1) {
      colon = s.lastIndexOf(':'); bytes = parseV4(s.slice(colon + 1));
      if (!bytes) return null;
      s = s.slice(0, colon + 1) + ((bytes[0] << 8) | bytes[1]).toString(16) + ':' + ((bytes[2] << 8) | bytes[3]).toString(16);
    }
    if (!/^[0-9a-f:]+$/i.test(s)) return null;
    halves = s.split('::'); if (halves.length > 2) return null;
    left = halves[0] ? halves[0].split(':') : [];
    right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    if (left.concat(right).some(function (x) { return !/^[0-9a-f]{1,4}$/i.test(x); })) return null;
    if (halves.length === 1) { if (left.length !== 8) return null; words = left; }
    else {
      if (left.length + right.length >= 8) return null;
      words = left.concat(Array(8 - left.length - right.length).fill('0'), right);
    }
    bytes = [];
    words.forEach(function (w) { var n = parseInt(w, 16); bytes.push(n >> 8, n & 255); });
    return {family: 6, bytes: bytes, zone: zone};
  }
  function parseTimestamp(value) {
    var s = text(value).trim();
    var m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,7}))?)?(Z|[+-]\d{2}:\d{2})?$/i.exec(s);
    if (!m) return NaN;
    var y = Number(m[1]), mon = Number(m[2]), day = Number(m[3]), hour = Number(m[4]), min = Number(m[5]), sec = Number(m[6] || 0);
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59) return NaN;
    var date = new Date(0); date.setUTCFullYear(y, mon - 1, day); date.setUTCHours(hour, min, sec, Number(((m[7] || '') + '000').slice(0, 3)));
    if (date.getUTCMonth() !== mon - 1 || date.getUTCDate() !== day) return NaN;
    var zone = m[8] || 'Z', offset = 0;
    if (zone.toUpperCase() !== 'Z') {
      var zh = Number(zone.slice(1, 3)), zm = Number(zone.slice(4, 6));
      if (zh > 23 || zm > 59) return NaN;
      offset = (zh * 60 + zm) * 60000 * (zone.charAt(0) === '+' ? 1 : -1);
    }
    return date.getTime() - offset;
  }
  function compile(input) {
    var errors = [], checks = [], state = {}, parsedIpCache = new Map();
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      if (input !== undefined && input !== null) errors.push('Filter state must be an object.');
      input = {};
    }
    fields.forEach(function (key) {
      var value = input[key];
      if (value === undefined || value === null) { state[key] = ''; return; }
      if (typeof value !== 'string' && typeof value !== 'number') {
        errors.push(key + ': enter a text or numeric value.'); state[key] = ''; return;
      }
      state[key] = text(value).trim();
      if (state[key].length > MAX_LENGTH) {
        errors.push(key + ': use at most ' + MAX_LENGTH + ' characters.');
        state[key] = state[key].slice(0, MAX_LENGTH);
      }
    });
    function parts(key) {
      var p = state[key].split(',').map(function (s) { return s.trim(); });
      if (p.length > MAX_ENTRIES || p.some(function (s) { return !s; })) {
        errors.push(key + ': use up to ' + MAX_ENTRIES + ' non-empty comma-separated values.'); return [];
      }
      return p;
    }
    function contains(key, getter) {
      var query = lower(state[key]); if (!query) return;
      checks.push(function (r) { return values(getter(r)).some(function (v) { return lower(v).indexOf(query) !== -1; }); });
    }
    function selection(key, getter) {
      var query = lower(state[key]); if (!query || query === 'any') return;
      checks.push(function (r) { return values(getter(r)).some(function (v) { return lower(v || 'Not recorded') === query; }); });
    }
    function numbers(key, rowKey, maximum) {
      if (!state[key]) return;
      var ranges = [];
      parts(key).forEach(function (part) {
        var m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(part), start, end;
        if (m) { start = Number(m[1]); end = m[2] === undefined ? start : Number(m[2]); }
        if (!m || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end > maximum || end < start) {
          errors.push(key + ': use numbers or ascending ranges from 0 to ' + maximum + '.'); return;
        }
        ranges.push([start,end]);
      });
      checks.push(function (r) {
        if (r[rowKey] === null || r[rowKey] === undefined || text(r[rowKey]).trim() === '') return false;
        var n = Number(r[rowKey]);
        return Number.isSafeInteger(n) && n >= 0 && n <= maximum && ranges.some(function (p) { return n >= p[0] && n <= p[1]; });
      });
    }
    function cachedIp(value) {
      var s = text(value);
      if (!parsedIpCache.has(s)) {
        if (parsedIpCache.size > 100000) parsedIpCache.clear();
        parsedIpCache.set(s, parseIp(s));
      }
      return parsedIpCache.get(s);
    }
    function ips(key, rowKey) {
      if (!state[key]) return;
      var networks = [];
      parts(key).forEach(function (part) {
        var p = part.split('/'), ip = parseIp(p[0]), bits = ip ? (ip.family === 4 ? 32 : 128) : 0;
        var prefix = p.length === 1 ? bits : /^\d+$/.test(p[1]) ? Number(p[1]) : NaN;
        if (!ip || p.length > 2 || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
          errors.push(key + ': use exact IPv4/IPv6 addresses or valid CIDR networks.'); return;
        }
        networks.push({ip: ip, prefix: prefix});
      });
      checks.push(function (r) {
        var ip = cachedIp(r[rowKey]); if (!ip) return false;
        return networks.some(function (n) {
          if (n.ip.family !== ip.family) return false;
          if (n.ip.zone && n.ip.zone !== ip.zone) return false;
          var whole = Math.floor(n.prefix / 8), tail = n.prefix % 8, i;
          for (i = 0; i < whole; i++) if (ip.bytes[i] !== n.ip.bytes[i]) return false;
          return tail === 0 || (ip.bytes[whole] >> (8 - tail)) === (n.ip.bytes[whole] >> (8 - tail));
        });
      });
    }
    function registrations(r) {
      return [r.ipRegistration].concat(values(r.domainRegistrations)).filter(function (v) { return v && typeof v === 'object'; });
    }
    contains('processName', function (r) { return r.processName; });
    contains('processPath', function (r) { return r.processPath; });
    contains('service', function (r) {
      return names(r.services).concat(values(r.serviceDetails).reduce(function (out, s) {
        if (s && typeof s === 'object') out.push(s.name, s.displayName, s.description); return out;
      }, []));
    });
    contains('dnsName', function (r) { return names(r.dnsNames); });
    contains('ptrName', function (r) { return names(r.ptrNames); });
    contains('organization', function (r) { return registrations(r).reduce(function (out, reg) {
      out.push(reg.organization, reg.name); return out;
    }, []); });
    contains('company', function (r) { return r.company; });
    contains('signer', function (r) { return r.signer; });
    contains('hash', function (r) { return r.sha256; });
    numbers('processId', 'processId', 2147483647);
    numbers('localPort', 'localPort', 65535);
    numbers('remotePort', 'remotePort', 65535);
    ips('localIp', 'localAddress'); ips('remoteIp', 'remoteAddress');
    if (state.country) {
      var countries = parts('country').map(function (c) { return c.toUpperCase(); });
      if (countries.some(function (c) { return !/^[A-Z]{2}$/.test(c); })) errors.push('country: use two-letter registration country codes, for example NL,US.');
      checks.push(function (r) { return registrations(r).some(function (reg) { return countries.indexOf(text(reg.country).toUpperCase()) !== -1; }); });
    }
    selection('signature', function (r) { return r.signatureStatus; });
    if (lower(state.direction) === 'unknown') {
      checks.push(function (r) { return !text(r.direction) || lower(r.direction).indexOf('unknown') === 0; });
    } else selection('direction', function (r) { return r.direction; });
    selection('metadataStatus', function (r) { return r.metadataStatus; });
    selection('rdapStatus', function (r) { var regs = registrations(r); return regs.length ? regs.map(function (reg) { return reg.status; }) : ['Not recorded']; });
    if (state.ipFamily && lower(state.ipFamily) !== 'any') {
      var family = lower(state.ipFamily);
      if (['ipv4','ipv6','unknown'].indexOf(family) === -1) errors.push('ipFamily: choose IPv4, IPv6 or Unknown.');
      checks.push(function (r) {
        var ip = cachedIp(missingRemote(r.remoteAddress) ? r.localAddress : r.remoteAddress);
        return (ip ? 'ipv' + ip.family : 'unknown') === family;
      });
    }
    ['dnsPresence','remotePresence'].forEach(function (key) {
      var query = lower(state[key]); if (!query || query === 'any') return;
      if (query !== 'missing' && query !== 'recorded') errors.push(key + ': choose recorded or missing.');
      checks.push(function (r) {
        var found = key === 'dnsPresence' ? names(r.dnsNames).length > 0 : !missingRemote(r.remoteAddress);
        return query === 'recorded' ? found : !found;
      });
    });
    var min = null, max = null;
    ['minObservations','maxObservations'].forEach(function (key) {
      if (!state[key]) return;
      var n = Number(state[key]);
      if (!/^\d+$/.test(state[key]) || !Number.isSafeInteger(n) || n < 0) errors.push(key + ': enter a non-negative whole number.');
      if (key === 'minObservations') min = n; else max = n;
    });
    if (min !== null && max !== null && min > max) errors.push('minObservations must not exceed maxObservations.');
    if (min !== null || max !== null) checks.push(function (r) {
      if (r.observations === null || r.observations === undefined || text(r.observations).trim() === '') return false;
      var n = Number(r.observations);
      return Number.isSafeInteger(n) && n >= 0 && (min === null || n >= min) && (max === null || n <= max);
    });
    var from = null, to = null;
    ['timeFrom','timeTo'].forEach(function (key) {
      if (!state[key]) return;
      var n = parseTimestamp(state[key]);
      if (!Number.isFinite(n)) errors.push(key + ': enter a valid ISO date and time (UTC when no offset is supplied).');
      if (key === 'timeFrom') from = n; else to = n;
    });
    if (from !== null && to !== null && from > to) errors.push('timeFrom must not be later than timeTo.');
    if (from !== null || to !== null) checks.push(function (r) {
      var a = parseTimestamp(r.firstSeen), b = parseTimestamp(r.lastSeen);
      if (!Number.isFinite(a)) a = b; if (!Number.isFinite(b)) b = a;
      if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
      var start = Math.min(a, b), end = Math.max(a, b);
      return (from === null || end >= from) && (to === null || start <= to);
    });
    return {errors: errors, matches: function (row) {
      return errors.length === 0 && !!row && typeof row === 'object' && checks.every(function (check) { return check(row); });
    }};
  }
  return {compile: compile, matches: function (row, state) { return compile(state).matches(row); },
    validate: function (state) { return compile(state).errors; }};
}));
