#!/usr/bin/env node
'use strict';
// usage: verify-refund-log-node <ledger.wal> [--witness F] [--ratchet F] [--expect-count N] [--expect-tip HEX] [--json]
//        verify-refund-log-node --encode <history.json> --out <new file> [--json]
// UNVERIFIED shim for the JavaScript target, in the trusted base; the same contract as verify_refund_log.py (its
// mirror, line for line in behaviour). Exit code starts at 3; it becomes 0 or 4 only by the return value of the proved
// Run (EncodeEntry: 0) AND only after the whole line was written to stdout (checked writeSync); else exit 3. build.py
// replaces the first line by `#!/usr/bin/env -S -i <absolute node>`: the caller's environment is EMPTIED before Node
// starts (no NODE_OPTIONS, NODE_PATH, DYLD_*). Any NODE_* variable that still arrives is refused. The compiled code is
// node-model/model.cjs beside this file; bignumber.js is the copy in node-model/node_modules (build.py).
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const USAGE = 'usage: verify-refund-log <ledger.wal> [--witness F] [--ratchet F] [--expect-count N] [--expect-tip HEX] [--json]\n' +
  '       verify-refund-log --encode <history.json> --out <new file> [--json]\n';
function emit(text) {
  let data = Buffer.from(text + '\n', 'utf8');
  while (data.length > 0) { const n = fs.writeSync(1, data); if (!(n > 0)) throw new Error('short write'); data = data.subarray(n); }
}
// A strict JSON reader: integers stay exact (tagged), a repeated key or a lone surrogate is an error.
function parseJson(s) {
  let i = 0;
  const fail = () => { throw new Error('json'); }, ws = () => { while (/[ \t\n\r]/.test(s[i] || '')) i++; };
  function str() {
    let out = ''; i++;
    for (;;) {
      const c = s[i++];
      if (c === undefined || c < ' ') fail();
      if (c === '"') break;
      if (c !== '\\') { out += c; continue; }
      const e = s[i++], m = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
      if (e in m) out += m[e];
      else if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(s.slice(i, i + 4))) { out += String.fromCharCode(parseInt(s.slice(i, i + 4), 16)); i += 4; } else fail();
    }
    if (/[\ud800-\udbff](?![\udc00-\udfff])|(^|[^\ud800-\udbff])[\udc00-\udfff]/.test(out)) fail();
    return out;
  }
  function val() {
    ws();
    const c = s[i];
    if (c === '"') return str();
    if (c === '{' || c === '[') {
      const obj = c === '{', o = obj ? new Map() : []; i++; ws();
      if (s[i] === (obj ? '}' : ']')) { i++; return o; }
      for (;;) {
        if (obj) { ws(); if (s[i] !== '"') fail(); const k = str(); ws(); if (s[i++] !== ':') fail(); if (o.has(k)) fail(); o.set(k, val()); } else o.push(val());
        ws(); const d = s[i++];
        if (d === (obj ? '}' : ']')) return o;
        if (d !== ',') fail();
      }
    }
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(s.slice(i));
    if (m) { i += m[0].length; return m[2] || m[3] ? { float: m[0] } : { int: m[0] }; }
    for (const [w, v] of [['true', true], ['false', false], ['null', null]]) if (s.startsWith(w, i)) { i += w.length; return v; }
    fail();
  }
  const v = val(); ws(); if (i !== s.length) fail(); return v;
}
function main(argv) {
  if (Object.keys(process.env).some((k) => k.startsWith('NODE_'))) throw new Error('NODE_* in the environment');
  const { V, rt, BigNumber } = require(path.join(path.dirname(fs.realpathSync(__filename)), 'node-model', 'model.cjs'));
  const text = (s) => rt.Seq.UnicodeFromString(s);
  const asJson = argv.includes('--json'), args = argv.filter((a) => a !== '--json');
  const unverifiable = (why) => [3, V.UnverifiableText(text(why), asJson).toVerbatimString(false)];
  const key = new BigNumber((BigInt('0x' + crypto.randomBytes(8).toString('hex')) % 2305843009213693951n).toString());
  const names = ['--witness', '--ratchet', '--expect-count', '--expect-tip', '--encode', '--out'], opts = new Map(), rest = [];
  while (args.length) { const a = args.shift(); if (names.includes(a) && args.length && !opts.has(a)) opts.set(a, args.shift()); else rest.push(a); }
  const encode = opts.has('--encode') || opts.has('--out');
  if ((encode && (rest.length || opts.size !== 2 || !opts.has('--encode') || !opts.has('--out'))) || (!encode && (rest.length !== 1 || rest[0].startsWith('-')))) {
    try { fs.writeSync(2, USAGE); } catch (e) { /* the usage text is optional */ }
    return unverifiable('USAGE');
  }
  const readBounded = (file, bound) => {
    const fd = fs.openSync(file, 'r'), buf = Buffer.alloc(bound + 1); let n = 0, k;
    try { while (n < buf.length && (k = fs.readSync(fd, buf, n, buf.length - n, null)) > 0) n += k; } finally { fs.closeSync(fd); }
    return buf.subarray(0, n);
  };
  const maxBytes = V.MaxBytes.toNumber(), maxRatchet = V.MaxRatchetBytes.toNumber();
  if (encode) {
    const out = path.resolve(opts.get('--out'));
    let exists = true;
    try { fs.lstatSync(out); } catch (e) { exists = false; }   // as Python's os.path.lexists
    if (exists) return unverifiable('OUT_EXISTS');
    let h;
    try {
      h = parseJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(readBounded(opts.get('--encode'), maxBytes)));
      const keys = (m, ks) => m instanceof Map && m.size === ks.length && ks.every((k) => m.has(k));
      const isInt = (x) => x !== null && typeof x === 'object' && !(x instanceof Map) && !Array.isArray(x) && 'int' in x;
      const ok = keys(h, ['charge', 'original', 'records']) && typeof h.get('charge') === 'string' && isInt(h.get('original')) &&
        Array.isArray(h.get('records')) && h.get('records').every((r) => keys(r, ['id', 'reason', 'amount']) &&
        typeof r.get('id') === 'string' && typeof r.get('reason') === 'string' && isInt(r.get('amount')));
      if (!ok) throw new Error('history form');
    } catch (e) { return unverifiable('ENCODE_INPUT'); }
    const recs = h.get('records');
    const [code, wal, line] = V.EncodeEntry(text(h.get('charge')), new BigNumber(h.get('original').int), rt.Seq.from(recs.map((r) => text(r.get('id')))),
      rt.Seq.from(recs.map((r) => new BigNumber(r.get('amount').int))), rt.Seq.from(recs.map((r) => text(r.get('reason')))), asJson, key);
    if (!code.isEqualTo(0)) return [3, line.toVerbatimString(false)];
    const tmp = path.join(path.dirname(out), '.' + path.basename(out) + '.tmp-' + process.pid);
    try {
      const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o644);
      try { let data = Buffer.from(wal); while (data.length) data = data.subarray(fs.writeSync(fd, data)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      fs.linkSync(tmp, out);   // fails if `out` appeared meanwhile: never replaced
    } catch (e) { return unverifiable(e.code === 'EEXIST' ? 'OUT_EXISTS' : 'OUT_WRITE_FAILED'); } finally { try { fs.unlinkSync(tmp); } catch (e) { /* gone */ } }
    return [0, line.toVerbatimString(false)];
  }
  let wal, rb = rt.Seq.of();
  try {
    wal = rt.Seq.from(readBounded(rest[0], maxBytes));
    if (opts.has('--ratchet')) rb = rt.Seq.from(readBounded(opts.get('--ratchet'), maxRatchet));
  } catch (e) { return unverifiable('UNREADABLE'); }
  const [code, line] = V.Run(wal, opts.has('--ratchet'), rb, opts.has('--expect-count'), text(opts.get('--expect-count') || ''),
    opts.has('--expect-tip'), text(opts.get('--expect-tip') || ''), opts.has('--witness'), asJson, key);
  return [code.toNumber(), line.toVerbatimString(false)];
}
let exitCode = 3;
try {
  const [result, line] = main(process.argv.slice(2));
  emit(line);
  exitCode = [0, 1, 3, 4].includes(result) ? result : 3;
} catch (e) {
  try { emit('UNVERIFIABLE_INTERNAL_ERROR reason=INTERNAL_ERROR'); } catch (e2) { /* nothing more can be said */ }
  exitCode = 3;
}
process.exit(exitCode);
