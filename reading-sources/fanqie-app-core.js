/* SPDX-License-Identifier: GPL-3.0-or-later
 * Fanqie App protocol adapter for Legado, 2026-10-30.
 * Signature algorithms adapted from naiyQAQ/fanqie-assistant (GPL-3.0)
 * https://github.com/naiyQAQ/fanqie-assistant/tree/main/src/crypto
 * Anonymous registration/query format cross-checked with hesan1232/fanqie.koplugin.
 * No account cookies, shared device IDs, or membership activation.
 * ES5: 64-bit operations use pairs of 32-bit words, without BigInt/WebCrypto.
 */
var FQApp = (function () {
  function hex(a) { var s = ''; for (var i = 0; i < a.length; i++) s += ('0' + (a[i] & 255).toString(16)).slice(-2); return s; }
  function unhex(s) { var a = []; for (var i = 0; i < s.length; i += 2) a.push(parseInt(s.substr(i, 2), 16)); return a; }
  function zeros(n) { var a = []; while (n-- > 0) a.push(0); return a; }
  function b64(a) {
    var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', s = '';
    for (var i = 0; i < a.length; i += 3) { var n = (a[i] << 16) | ((a[i + 1] || 0) << 8) | (a[i + 2] || 0); s += t.charAt(n >>> 18 & 63) + t.charAt(n >>> 12 & 63) + (i + 1 < a.length ? t.charAt(n >>> 6 & 63) : '=') + (i + 2 < a.length ? t.charAt(n & 63) : '='); }
    return s;
  }
  function unb64(s) {
    var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', a = [], n = 0, bits = 0;
    s = String(s).replace(/\s/g, '');
    for (var i = 0; i < s.length; i++) { var v = t.indexOf(s.charAt(i)); if (v < 0) continue; n = (n << 6) | v; bits += 6; if (bits >= 8) { bits -= 8; a.push(n >>> bits & 255); } }
    return a;
  }
  function pad(a) { var n = 16 - a.length % 16, b = a.slice(); for (var i = 0; i < n; i++) b.push(n); return b; }
  function rol(x, n) { n &= 31; return (x << n) | (x >>> ((32 - n) & 31)); }
  function sm3(a) {
    var m = a.slice(), bitLength = a.length * 8, state = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
    m.push(128); while (m.length % 64 !== 56) m.push(0);
    var len = zeros(8); for (var j = 7; j >= 0; j--) { len[j] = bitLength % 256; bitLength = Math.floor(bitLength / 256); } m = m.concat(len);
    for (var offset = 0; offset < m.length; offset += 64) {
      var w = [], ewords = [];
      for (var i = 0; i < 16; i++) { var p = offset + i * 4; w[i] = (m[p] << 24) | (m[p + 1] << 16) | (m[p + 2] << 8) | m[p + 3]; }
      for (i = 16; i < 68; i++) { var v = w[i - 16] ^ w[i - 9] ^ rol(w[i - 3], 15); w[i] = v ^ rol(v, 15) ^ rol(v, 23) ^ rol(w[i - 13], 7) ^ w[i - 6]; }
      for (i = 0; i < 64; i++) ewords[i] = w[i] ^ w[i + 4];
      var A = state[0], B = state[1], C = state[2], D = state[3], E = state[4], F = state[5], G = state[6], H = state[7];
      for (i = 0; i < 64; i++) {
        var ss1 = rol((rol(A, 12) + E + rol(i < 16 ? 0x79cc4519 : 0x7a879d8a, i)) | 0, 7), ss2 = ss1 ^ rol(A, 12);
        var tt1 = ((i < 16 ? A ^ B ^ C : (A & B) | (A & C) | (B & C)) + D + ss2 + ewords[i]) | 0;
        var tt2 = ((i < 16 ? E ^ F ^ G : (E & F) | (~E & G)) + H + ss1 + w[i]) | 0;
        D = C; C = rol(B, 9); B = A; A = tt1; H = G; G = rol(F, 19); F = E; E = tt2 ^ rol(tt2, 9) ^ rol(tt2, 17);
      }
      var end = [A, B, C, D, E, F, G, H]; for (i = 0; i < 8; i++) state[i] ^= end[i];
    }
    var out = []; for (var k = 0; k < 8; k++) out.push(state[k] >>> 24, state[k] >>> 16 & 255, state[k] >>> 8 & 255, state[k] & 255); return out;
  }
  function read32(a, p) { return (a[p] | a[p + 1] << 8 | a[p + 2] << 16 | a[p + 3] << 24) >>> 0; }
  function longAt(a, p) { return [read32(a, p), read32(a, p + 4)]; }
  function longBytes(v) { var a = []; for (var i = 0; i < 2; i++) for (var j = 0; j < 4; j++) a.push(v[i] >>> (j * 8) & 255); return a; }
  function xor(a, b) { return [(a[0] ^ b[0]) >>> 0, (a[1] ^ b[1]) >>> 0]; }
  function and(a, b) { return [(a[0] & b[0]) >>> 0, (a[1] & b[1]) >>> 0]; }
  function add(a, b) { var n = (a[0] >>> 0) + (b[0] >>> 0); return [n >>> 0, ((a[1] >>> 0) + (b[1] >>> 0) + (n >= 4294967296 ? 1 : 0)) >>> 0]; }
  function ror(a, n) { n &= 63; if (n >= 32) { a = [a[1], a[0]]; n -= 32; } if (!n) return a.slice(); return [((a[0] >>> n) | (a[1] << (32 - n))) >>> 0, ((a[1] >>> n) | (a[0] << (32 - n))) >>> 0]; }
  function simonKeys(key) {
    var k = key.slice(), z = [0x046d678b, 0x3dc94c3a];
    for (var i = 4; i < 72; i++) { var t = xor(ror(k[i - 1], 3), k[i - 3]); t = xor(t, ror(t, 1)); var bit = (ror(z, (i - 4) % 62)[0] & 1); k.push(xor(xor([~k[i - 4][0] >>> 0, ~k[i - 4][1] >>> 0], t), [bit ^ 3, 0])); }
    return k;
  }
  function simon(a, key) { var x = a[0], y = a[1]; for (var i = 0; i < 72; i++) { var t = y; y = xor(xor(xor(x, and(ror(y, 63), ror(y, 56))), ror(y, 62)), key[i]); x = t; } return longBytes(x).concat(longBytes(y)); }
  function speck(key, plain) {
    var ks = [longAt(key, 0)], ls = [longAt(key, 8), longAt(key, 16), longAt(key, 24)];
    for (var i = 0; i < 33; i++) { var v = xor(add(ror(ls[i], 8), ks[i]), [i, 0]); ls.push(v); ks.push(xor(v, ror(ks[i], 61))); }
    var input = pad(plain), out = [];
    for (var p = 0; p < input.length; p += 16) { var y = longAt(input, p), x = longAt(input, p + 8); for (i = 0; i < 34; i++) { x = xor(ks[i], add(ror(x, 8), y)); y = xor(x, ror(y, 61)); } out = out.concat(longBytes(y), longBytes(x)); }
    return out;
  }
  function PB() { this.a = []; }
  PB.prototype.v = function (v) { v >>>= 0; while (v >= 128) { this.a.push((v & 127) | 128); v >>>= 7; } this.a.push(v & 127); return this; };
  PB.prototype.num = function (n, v) { return this.v(n << 3).v(v); };
  PB.prototype.bytes = function (n, a) { this.v((n << 3) | 2).v(a.length); this.a = this.a.concat(a); return this; };
  function leDecimal(s) { var out = []; for (var i = 0; i < 8; i++) { var next = '', rem = 0; for (var j = 0; j < s.length; j++) { var n = rem * 10 + Number(s.charAt(j)), q = Math.floor(n / 256); rem = n % 256; if (next || q) next += q; } out.push(rem); s = next || '0'; } return out; }
  function create(H) {
    var shared = unhex('ac25c67ddd8f38c1b37a2348828e222e'), signKey = unhex('ac1adaae95a7af94a5114ab3b3a97dd80050aa0a39314c40528caec95256c28c');
    function text(pb, n, s) { return pb.bytes(n, H.utf8(s)); }
    function sign(url, body, now) {
      var query = url.split('?')[1] || '', stub = body ? H.md5(H.utf8(body)) : zeros(16), device = /(?:^|&)device_id=([^&]+)/.exec(query), version = /(?:^|&)version_name=([^&]+)/.exec(query);
      var rand = read32(H.random(4), 0) % 2147483647, timestamp = Math.floor(now / 1000), pb = new PB();
      pb.num(1, 0x20200929 * 2).num(2, 2).num(3, rand);
      text(pb, 4, '1967'); text(pb, 5, device ? decodeURIComponent(device[1]) : ''); text(pb, 6, '1611921764'); text(pb, 7, version ? decodeURIComponent(version[1]) : ''); text(pb, 8, 'v04.04.05-ov-android');
      pb.num(9, 134744640).bytes(10, zeros(8)).num(11, 0).num(12, timestamp * 2).bytes(13, sm3(stub).slice(0, 6)).bytes(14, sm3(query ? H.utf8(query) : zeros(16)).slice(0, 6));
      pb.bytes(15, new PB().num(1, 1).num(2, 1).num(3, 1).num(7, 3348294860).a); text(pb, 16, ''); text(pb, 20, 'none'); pb.num(21, 738);
      var sub = new PB(); text(sub, 1, 'NX551J'); sub.num(2, 8196).num(4, 2162219008); pb.bytes(23, sub.a).num(25, 2);
      var keyData = sm3(signKey.concat([242, 129, 97, 111], signKey)), sk = simonKeys([longAt(keyData, 0), longAt(keyData, 8), longAt(keyData, 16), longAt(keyData, 24)]), padded = pad(pb.a), encrypted = [];
      for (var p = 0; p < padded.length; p += 16) encrypted = encrypted.concat(simon([longAt(padded, p), longAt(padded, p + 8)], sk));
      var inner = [242, 247, 252, 255, 242, 247, 252, 255].concat(encrypted);
      for (var i = 8; i < inner.length; i++) inner[i] ^= inner[i % 8]; inner.reverse();
      var argus = b64([242, 129].concat(H.aes(H.md5(signKey.slice(0, 16)), H.md5(signKey.slice(16)), [166, 110, 173, 159, 119, 1, 208, 12, 24].concat(inner, [97, 111]), false)));
      var random4 = H.random(4), ladonKey = H.utf8(hex(H.md5(random4.concat(H.utf8('1967'))))), ladon = b64(random4.concat(speck(ladonKey, H.utf8(timestamp + '-1611921764-1967'))));
      var out = { 'x-argus': argus, 'x-ladon': ladon, 'x-khronos': String(timestamp), 'x-ss-req-ticket': String(now) }; if (body) out['X-SS-STUB'] = hex(stub); return out;
    }
    var cacheName = 'fanqie.app.protocol.device.v1';
    function save(d) { H.save(cacheName, JSON.stringify(d)); }
    function query(d, extra) {
      var pairs = [['iid', d.install_id], ['device_id', d.device_id], ['ac', 'wifi'], ['channel', '43536163a'], ['aid', '1967'], ['app_name', 'novelapp'], ['version_code', '73733'], ['version_name', '7.3.7.33'], ['device_platform', 'android'], ['os', 'android'], ['ssmix', 'a'], ['device_type', 'P30'], ['device_brand', 'HUAWEI'], ['language', 'zh'], ['os_api', '31'], ['os_version', '12'], ['manifest_version_code', '73733'], ['resolution', '1280*720'], ['dpi', '240'], ['update_version_code', '73733'], ['_rticket', String(H.now())], ['host_abi', 'arm64-v8a'], ['cdid', d.cdid], ['openudid', d.openudid]].concat(extra || []), out = [];
      for (var i = 0; i < pairs.length; i++) out.push(encodeURIComponent(pairs[i][0]) + '=' + encodeURIComponent(pairs[i][1])); return out.join('&');
    }
    function parseResponse(s, label) {
      s = String(s || ''); if (!s.trim()) throw new Error(label + '返回空响应，请稍后重试或切换网络');
      try { return JSON.parse(s.replace(/("(?:device_id|install_id)"\s*:\s*)(\d{16,})/g, '$1"$2"')); } catch (e) { throw new Error(label + '返回非 JSON 内容，请检查网络'); }
    }
    function uuid() { var h = hex(H.random(16)); return h.slice(0, 8) + '-' + h.slice(8, 12) + '-4' + h.slice(13, 16) + '-8' + h.slice(17, 20) + '-' + h.slice(20); }
    function device() {
      var cached = H.load(cacheName), d; if (cached) { try { d = JSON.parse(String(cached)); if (d.device_id && d.install_id) return d; } catch (ignore) {} }
      d = { cdid: uuid(), openudid: hex(H.random(8)), clientudid: uuid() }; var now = H.now();
      var header = { display_name: '番茄小说', update_version_code: 73733, manifest_version_code: 73733, aid: 1967, channel: '43536163a', package: 'com.dragon.read', app_version: '7.3.7.33', version_code: 73733, sdk_version: '3.7.2.cn', os: 'Android', os_version: '12', os_api: 31, device_model: 'P30', device_brand: 'HUAWEI', device_manufacturer: 'HUAWEI', cpu_abi: 'arm64-v8a', density_dpi: 240, resolution: '1280x720', language: 'zh', timezone: 8, access: 'wifi', not_request_sender: 0, rom_version: 'S643.217451.03386707', cdid: d.cdid, openudid: d.openudid, clientudid: d.clientudid, region: 'CN', tz_name: 'Asia/Shanghai', tz_offset: 28800, sim_region: 'cn', req_id: uuid(), apk_first_install_time: now - 86400000, is_system_app: 0, sdk_flavor: 'china' };
      var q = query({ install_id: '0', device_id: '0', cdid: d.cdid, openudid: d.openudid });
      var res = parseResponse(H.request('https://log.snssdk.com/service/2/device_register/?' + q, JSON.stringify({ magic_tag: 'ss_app_log', header: header, _gen_time: now }), { 'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'com.dragon.read/73733 (Linux; U; Android 12; zh_CN; P30; Build/S643.217451.03386707;tt-ok/3.12.13.4-tiktok)' }), '匿名设备注册');
      d.device_id = String(res.device_id_str || res.device_id || ''); d.install_id = String(res.install_id_str || res.install_id || '');
      if (!/^\d+$/.test(d.device_id) || d.device_id === '0' || !/^\d+$/.test(d.install_id) || d.install_id === '0') throw new Error('匿名设备注册失败，请稍后重试');
      save(d); return d;
    }
    var base = 'https://api5-normal-sinfonlinec.fqnovel.com/reading';
    function call(d, path, extra, body) {
      var url = base + path + '?' + query(d, extra), h = sign(url, body, H.now()); h['User-Agent'] = 'com.dragon.read'; h.Cookie = 'install_id=' + d.install_id; if (body) h['Content-Type'] = 'application/json';
      var res = parseResponse(H.request(url, body, h), '番茄 App 接口');
      if (Number(res.code) !== 0) throw new Error('番茄 App 接口失败：' + String(res.message || res.msg || res.code)); return res.data;
    }
    function registerKey(d) {
      var iv = H.random(16), payload = leDecimal(d.device_id).concat(zeros(8)), body = JSON.stringify({ content: b64(iv.concat(H.aes(shared, iv, payload, false))), keyver: 1 });
      var res = call(d, '/crypt/registerkey', [], body); if (!res || !res.key) throw new Error('未取得正文解密密钥');
      var raw = unb64(res.key), key = H.aes(shared, raw.slice(0, 16), raw.slice(16), true);
      if (key.length !== 16) throw new Error('正文密钥长度异常'); d.key = hex(key); d.keyver = res.keyver; d.keyTime = H.now(); save(d);
    }
    function chapter(bookId, itemId) {
      bookId = String(bookId); itemId = String(itemId); if (!/^\d+$/.test(bookId) || !/^\d+$/.test(itemId)) throw new Error('未取得正确的番茄书籍或章节编号');
      var d = device(); if (!d.key || H.now() - Number(d.keyTime || 0) > 604800000) registerKey(d);
      for (var attempt = 0; attempt < 2; attempt++) {
        var data = call(d, '/reader/batch_full/v', [['item_ids', itemId], ['key_register_ts', '0'], ['book_id', bookId], ['req_type', '1']]), row = data && data[itemId]; if (Array.isArray(row)) row = row[0];
        if (!row) throw new Error('番茄 App 未返回该章节');
        if (row.need_pay === true || row.needPay === true) throw new Error('本章需要在官方平台购买后阅读');
        if (!row.content || row.content === 'Invalid' || String(row.key_version) !== String(d.keyver)) { if (attempt === 0) { registerKey(d); continue; } throw new Error('正文密钥失效，请稍后重试'); }
        var blob = unb64(row.content), plain;
        try { plain = Number(row.crypt_status) === 0 ? H.aes(unhex(d.key), blob.slice(0, 16), blob.slice(16), true) : H.utf8(row.content); if (Number(row.compress_status) === 1 || (plain[0] === 31 && plain[1] === 139)) plain = H.gunzip(plain); } catch (e) { if (attempt === 0) { registerKey(d); continue; } throw new Error('番茄 App 正文解密失败：' + e.message); }
        var html = H.decode(plain), result = html;
        if (/^\s*[{\[]/.test(html)) { var obj = JSON.parse(html); result = obj.content || (obj.data && obj.data.content) || ''; }
        result = String(result).replace(/<\s*(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, '').replace(/<\/?(?:p|div|section|br|h[1-6])\b[^>]*>/gi, '\n').replace(/<[^>]*>/g, '').replace(/&#(x[0-9a-f]+|\d+);/gi, function (_, n) { var c = n.charAt(0).toLowerCase() === 'x' ? parseInt(n.slice(1), 16) : Number(n); return c <= 65535 ? String.fromCharCode(c) : String.fromCharCode(55296 + ((c - 65536) >> 10), 56320 + ((c - 65536) & 1023)); }).replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&#39;/gi, "'").replace(/[ \t]+\n/g, '\n').replace(/\n[ \t]+/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
        if (!result || /会员登录后，可在网页畅读全文/.test(result)) throw new Error('番茄 App 未返回完整正文');
        return { title: row.title, content: result, rawChars: html.length, paragraphs: row.paragraphs_num };
      }
      throw new Error('未取得番茄章节');
    }
    return { sign: sign, chapter: chapter, registerKey: registerKey, device: device, sm3: sm3, speck: speck, simon: simon, simonKeys: simonKeys };
  }
  function android(bridge, cacheStore) {
    var J = Packages.java, C = Packages.javax.crypto, random = new J.security.SecureRandom();
    // Use Legado's byte-array helper; current versions prohibit Java reflection.
    function jbytes(a) { return bridge.hexDecodeToByteArray(hex(a)); }
    function bytes(a) { var out = []; for (var i = 0; i < a.length; i++) out.push(a[i] & 255); return out; }
    return create({
      now: function () { return new Date().getTime(); },
      random: function (n) { var a = jbytes(zeros(n)); random.nextBytes(a); return bytes(a); },
      utf8: function (s) { return bytes(new J.lang.String(String(s)).getBytes('UTF-8')); },
      decode: function (a) { return String(new J.lang.String(jbytes(a), 'UTF-8')); },
      md5: function (a) { return bytes(J.security.MessageDigest.getInstance('MD5').digest(jbytes(a))); },
      aes: function (key, iv, a, decrypt) { var cipher = C.Cipher.getInstance('AES/CBC/PKCS5Padding'); cipher.init(decrypt ? 2 : 1, new C.spec.SecretKeySpec(jbytes(key), 'AES'), new C.spec.IvParameterSpec(jbytes(iv))); return bytes(cipher.doFinal(jbytes(a))); },
      gunzip: function (a) { var input = new J.util.zip.GZIPInputStream(new J.io.ByteArrayInputStream(jbytes(a))), output = new J.io.ByteArrayOutputStream(), buf = jbytes(zeros(4096)); try { var n; while ((n = input.read(buf)) !== -1) { output.write(buf, 0, n); if (output.size() > 4194304) throw new Error('章节数据超过大小限制'); } return bytes(output.toByteArray()); } finally { input.close(); output.close(); } },
      // Older Legado versions expose only ajax(Object), so pass a single Java String.
      request: function (url, body, h) { var options = { headers: h, retry: 0, timeout: 18000 }; if (typeof body !== 'undefined') { options.method = 'POST'; options.body = body; } return String(bridge.ajax(new J.lang.String(url + ',' + JSON.stringify(options)))); },
      load: function (key) { return cacheStore.get(key); },
      save: function (key, value) { cacheStore.put(key, value); }
    });
  }
  return { create: create, android: android, hex: hex, unhex: unhex, b64: b64, unb64: unb64, leDecimal: leDecimal };
}());
if (typeof module !== 'undefined' && module.exports) module.exports = FQApp;
