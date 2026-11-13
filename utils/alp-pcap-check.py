#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
alp-pcap-check - validate ALP pcap files (LINKTYPE_ATSC_ALP, 289).

  ./alp-pcap-check.py capture.pcap                  # check one file
  ./alp-pcap-check.py capture.pcap known-good.pcap  # compare side by side
  ./alp-pcap-check.py capture.pcap --clean ok.pcap  # drop records with framing errors
  ./alp-pcap-check.py capture.pcap --dump 8         # hex + parsed header of first 8

Checks the pcap container (header, record headers, truncation) and every ALP
packet against A/330: header form, declared length vs record length,
segmentation sequence, IPv4 header (version, length, checksum) and UDP
length. Prints counts, the first problems found, and the size distribution.
Framing errors (wrong length, reserved type, cut-off header, segment
sequence) mean the record isn't a well-formed ALP packet. Content warnings
(IPv4 checks) are reported separately. With --clean, records with framing
errors are dropped, so you can see whether they are what upsets a consumer.
"""
import argparse, collections, struct, sys

LINKTYPE_ATSC_ALP = 289
TYPE_NAMES = {0: 'IPv4', 1: 'reserved1', 2: 'compressed IP', 3: 'reserved3',
              4: 'signalling', 5: 'reserved5', 6: 'type ext', 7: 'MPEG-2 TS'}
SIG_HDR = 5  # link-layer signalling information header (outside the length)


def alp_layout(b):
    """Return (form, header_len, payload_len, extra) per A/330, or raise
    ValueError if the header itself is cut short."""
    if len(b) < 2:
        raise ValueError('shorter than the 2-byte base header')
    t, pc, b3 = b[0] >> 5, (b[0] >> 4) & 1, (b[0] >> 3) & 1
    length = ((b[0] & 7) << 8) | b[1]
    extra = {}

    def ext(hdr, flags):
        sif, hef = (flags >> 1) & 1, flags & 1
        extra['sif'], extra['hef'] = sif, hef
        if sif:
            if len(b) < hdr + 1:
                raise ValueError('sub-stream id cut short')
            extra['sid'] = b[hdr]
            hdr += 1
        if hef:
            if len(b) < hdr + 2:
                raise ValueError('header extension cut short')
            extra['ext_type'] = b[hdr]
            extra['ext_len'] = b[hdr + 1] + 1
            hdr += 2 + b[hdr + 1] + 1
        return hdr

    if pc == 0 and b3 == 0:
        form, hdr = 'single', 2
    elif pc == 0:
        if len(b) < 3:
            raise ValueError('HM=1 header cut short')
        form = 'single+hdr'
        length |= (b[2] >> 3) << 11
        hdr = ext(3, b[2])
    elif b3 == 0:
        if len(b) < 3:
            raise ValueError('segment header cut short')
        form = 'segment'
        extra['seq'] = b[2] >> 3
        extra['last'] = (b[2] >> 2) & 1
        hdr = ext(3, b[2])
    else:
        if len(b) < 3:
            raise ValueError('concatenation header cut short')
        form = 'concat'
        length |= (b[2] >> 4) << 11
        count = ((b[2] >> 1) & 7) + 2
        sif = b[2] & 1
        hdr = 3 + ((count - 1) * 12 + 7) // 8 + sif
        extra['count'] = count
        extra['driver_len'] = 2 + length   # how cxd28xx alp.c frames it
    if t == 4 and form in ('single', 'single+hdr'):
        hdr += SIG_HDR
    return t, form, hdr, length, extra


def ip_checksum(h):
    s = sum(struct.unpack('>%dH' % (len(h) // 2), h))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def check_ipv4(p):
    if len(p) < 20:
        return 'IPv4 shorter than 20 bytes'
    if p[0] >> 4 != 4:
        return 'IP version %d' % (p[0] >> 4)
    ihl = (p[0] & 15) * 4
    if ihl < 20 or ihl > len(p):
        return 'bad IHL %d' % ihl
    tot = struct.unpack('>H', p[2:4])[0]
    if tot != len(p):
        return 'IP total length %d != payload %d' % (tot, len(p))
    if not ip_checksum(p[:ihl]):
        return 'IP header checksum wrong'
    if p[9] == 17 and len(p) >= ihl + 8:
        ulen = struct.unpack('>H', p[ihl + 4:ihl + 6])[0]
        if ulen != tot - ihl:
            return 'UDP length %d != %d' % (ulen, tot - ihl)
    return None


class Report:
    def __init__(self, name):
        self.name = name
        self.problems = []          # (record#, text)
        self.problem_kinds = collections.Counter()
        self.types = collections.Counter()
        self.forms = collections.Counter()
        self.sizes = []
        self.records = 0
        self.bytes = 0
        self.container = []
        self.linktype = None
        self.ts_backwards = 0
        self.good = []              # raw record bytes that passed

        self.warnings = []
        self.warning_kinds = collections.Counter()
        self.hm_detail = collections.Counter()

    def bad(self, n, kind, text):
        self.problem_kinds[kind] += 1
        if len(self.problems) < 25:
            self.problems.append((n, text))

    def warn(self, n, kind, text):
        self.warning_kinds[kind] += 1
        if len(self.warnings) < 10:
            self.warnings.append((n, text))


def check_file(path, keep_good=False):
    r = Report(path)
    try:
        data = open(path, 'rb').read()
    except OSError as e:
        r.container.append(str(e))
        return r
    if len(data) < 24:
        r.container.append('file shorter than the 24-byte pcap header')
        return r
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        en, nsres = '<', False
    elif magic == b'\xa1\xb2\xc3\xd4':
        en, nsres = '>', False
    elif magic == b'\x4d\x3c\xb2\xa1':
        en, nsres = '<', True
    elif magic == b'\xa1\xb2\x3c\x4d':
        en, nsres = '>', True
    elif magic == b'\x0a\x0d\x0d\x0a':
        r.container.append('pcapng, not classic pcap (convert: editcap -F pcap in out)')
        return r
    else:
        r.container.append('not a pcap file (magic %s)' % magic.hex())
        return r
    vmaj, vmin, _, _, snaplen, linktype = struct.unpack(en + 'HHiIII', data[4:24])
    r.linktype, r.snaplen, r.header = linktype, snaplen, data[:24]
    if linktype != LINKTYPE_ATSC_ALP:
        r.container.append('link type %d, expected %d (ATSC ALP)' % (linktype, LINKTYPE_ATSC_ALP))
    if (vmaj, vmin) != (2, 4):
        r.container.append('pcap version %d.%d (expected 2.4)' % (vmaj, vmin))
    r.nsres = nsres

    pos, last_ts, seg_expect = 24, None, None
    while pos < len(data):
        n = r.records + 1
        if pos + 16 > len(data):
            r.container.append('record %d: header truncated at end of file (%d bytes left)'
                               % (n, len(data) - pos))
            break
        sec, frac, incl, orig = struct.unpack(en + 'IIII', data[pos:pos + 16])
        if incl > max(snaplen, 65535) or pos + 16 + incl > len(data):
            r.container.append('record %d: incl_len %d runs past end of file / snaplen'
                               % (n, incl))
            break
        rec = data[pos + 16:pos + 16 + incl]
        raw = data[pos:pos + 16 + incl]
        pos += 16 + incl
        r.records += 1
        r.bytes += incl
        r.sizes.append(incl)
        ok = True
        if incl != orig:
            r.bad(n, 'truncated record', 'record %d: captured %d of %d bytes' % (n, incl, orig))
            ok = False
        ts = sec + frac / (1e9 if nsres else 1e6)
        if last_ts is not None and ts < last_ts:
            r.ts_backwards += 1
        last_ts = ts
        if incl == 0:
            r.bad(n, 'empty record', 'record %d: empty' % n)
            continue
        if (len(rec) >= 40 and rec[0] >> 4 == 6 and
                40 + struct.unpack('>H', rec[4:6])[0] == len(rec)):
            r.bad(n, 'IPv6 packet, not ALP', 'record %d: an IPv6 packet (next header %d), not ALP: '
                  'the capturing host\'s own traffic on the interface' % (n, rec[6]))
            continue
        try:
            t, form, hlen, plen, extra = alp_layout(rec)
        except ValueError as e:
            r.bad(n, 'bad header', 'record %d: %s (bytes %s)' % (n, e, rec[:8].hex(' ')))
            continue
        r.types[t] += 1
        r.forms[form] += 1
        if form == 'single+hdr':
            r.hm_detail['SIF=%d HEF=%d%s' % (extra['sif'], extra['hef'],
                        ' ext type 0x%02x len %d' % (extra['ext_type'], extra['ext_len'])
                        if extra['hef'] else '')] += 1
        want = hlen + plen
        if want != incl:
            kind = '%s length mismatch' % form
            hint = ''
            if form == 'concat' and extra['driver_len'] == incl:
                hint = ' (matches the driver\'s framing, not A/330)'
            elif form == 'segment' and want == incl + 1:
                hint = ' (1 byte short: driver omits the segment header byte)'
            r.bad(n, kind, 'record %d: %s %s header says %d bytes, record is %d%s; bytes %s'
                  % (n, TYPE_NAMES[t], form, want, incl, hint, rec[:8].hex(' ')))
            ok = False
        if form == 'segment':
            if seg_expect is not None and extra['seq'] != seg_expect:
                r.bad(n, 'segment sequence', 'record %d: segment %d, expected %d'
                      % (n, extra['seq'], seg_expect))
            seg_expect = None if extra['last'] else extra['seq'] + 1
        elif seg_expect is not None:
            r.bad(n, 'segment sequence', 'record %d: segmented packet ended without last segment' % n)
            seg_expect = None
        if ok and t == 0 and form in ('single', 'single+hdr'):
            err = check_ipv4(rec[hlen:hlen + plen])
            if err:
                r.warn(n, 'IPv4 content (%s)' % form, 'record %d (%s, payload %d bytes): %s'
                       % (n, form, plen, err))
        if ok and t in (1, 3, 5):
            r.bad(n, 'reserved type', 'record %d: reserved ALP packet type %d' % (n, t))
            ok = False
        if ok and keep_good:
            r.good.append(raw)
    return r


def summarize(r):
    out = ['== %s' % r.name]
    for c in r.container:
        out.append('  CONTAINER: ' + c)
    if r.linktype is None:
        return '\n'.join(out)
    out.append('  records %d, %d bytes, link type %d, snaplen %d, %s timestamps'
               % (r.records, r.bytes, r.linktype, r.snaplen,
                  'nanosecond' if r.nsres else 'microsecond'))
    if r.sizes:
        s = sorted(r.sizes)
        out.append('  record size: min %d, median %d, max %d; over 1500: %d, over 2048: %d'
                   % (s[0], s[len(s) // 2], s[-1], sum(x > 1500 for x in s), sum(x > 2048 for x in s)))
    out.append('  types: ' + ', '.join('%s %d' % (TYPE_NAMES[t], c) for t, c in sorted(r.types.items())))
    out.append('  forms: ' + ', '.join('%s %d' % (f, c) for f, c in sorted(r.forms.items())))
    if r.ts_backwards:
        out.append('  timestamps went backwards %d times' % r.ts_backwards)
    if r.hm_detail:
        out.append('  single+hdr detail: ' + ', '.join('%s: %d' % (k, c) for k, c in r.hm_detail.most_common(6)))
    total_bad = sum(r.problem_kinds.values())
    out.append('  framing errors: %d%s' % (total_bad, ' - OK' if not total_bad and not r.container else ''))
    for k, c in r.problem_kinds.most_common():
        out.append('    %-28s %d' % (k, c))
    if r.problems:
        out.append('  first framing errors:')
        out += ['    ' + t for _, t in r.problems]
    if r.warning_kinds:
        out.append('  content warnings: ' + ', '.join('%s %d' % (k, c) for k, c in r.warning_kinds.most_common()))
        out += ['    ' + t for _, t in r.warnings[:5]]
    return '\n'.join(out)


def dump(path, count):
    data = open(path, 'rb').read()
    en = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    pos = 24
    print('-- first %d records of %s' % (count, path))
    for n in range(1, count + 1):
        if pos + 16 > len(data):
            break
        incl = struct.unpack(en + 'I', data[pos + 8:pos + 12])[0]
        rec = data[pos + 16:pos + 16 + incl]
        pos += 16 + incl
        try:
            t, form, hlen, plen, extra = alp_layout(rec)
            desc = '%s %s hdr=%d payload=%d %s' % (TYPE_NAMES[t], form, hlen, plen,
                    ' '.join('%s=%s' % kv for kv in extra.items()))
        except ValueError as e:
            desc = 'unparsable: %s' % e
        print('  #%d len %d: %s' % (n, incl, desc))
        print('     ' + rec[:48].hex(' ') + (' ...' if incl > 48 else ''))
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--clean', metavar='OUT', help='write the first file to OUT without records that have framing errors')
    ap.add_argument('--dump', metavar='N', type=int, default=0, help='hex dump and parse the first N records of each file')
    a = ap.parse_args()
    for i, f in enumerate(a.files):
        if a.dump:
            dump(f, a.dump)
        r = check_file(f, keep_good=(i == 0 and bool(a.clean)))
        print(summarize(r))
        if i == 0 and a.clean and r.linktype is not None:
            with open(a.clean, 'wb') as o:
                o.write(r.header)
                for g in r.good:
                    o.write(g)
            print('  wrote %d of %d records to %s' % (len(r.good), r.records, a.clean))
        print()


if __name__ == '__main__':
    main()
