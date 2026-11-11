#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
alp-pcap-merge - combine ALP pcaps of one channel captured with different PLP
selections (e.g. PLPs 0+1, then PLP 16, on a channel where no receiver can
decode all three at once) into one pcap for tools that expect a single
capture.

  alp-pcap-merge.py -o ch25.pcap p01.pcap p16.pcap

Modes, for how the second and later files' packets are placed:
  --append      (default) after the first file's packets, real timestamps
                kept. The output is honest about when each packet was
                received; it just has the second capture after the first.
  --interleave  sorted by real timestamp (same as --append for back-to-back
                captures; differs only if the captures overlapped in time).
  --align       each later file shifted so it starts when the first one did,
                then interleaved, so the result looks like one simultaneous
                capture. Timestamps of the shifted packets are synthetic:
                don't use this for anything that measures timing between
                PLPs.

Inputs: classic pcap, micro- or nanosecond, either byte order, LINKTYPE 289.
Output: nanosecond pcap (magic a1b23c4d), as alp-capture writes.

L1 string: the capture's .txt (L1-Basic + L1-Detail) describes the whole
channel, whichever PLPs were decoded, so the first input's .txt is copied to
the output's .txt. If the inputs' .txt files differ (the broadcaster changed
the configuration between captures), you get a warning.
"""
import argparse
import base64
import heapq
import os
import shutil
import struct
import sys

LINKTYPE_ATSC_ALP = 289
MAGICS = {  # magic as read little-endian -> (byte order, ns per tick unit)
    0xa1b2c3d4: ('<', 1000), 0xa1b23c4d: ('<', 1),
    0xd4c3b2a1: ('>', 1000), 0x4d3cb2a1: ('>', 1),
}


class Pcap:
    def __init__(self, path):
        self.path = path
        self.f = open(path, 'rb')
        gh = self.f.read(24)
        if len(gh) < 24:
            sys.exit('%s: not a pcap (too short)' % path)
        magic = struct.unpack('<I', gh[:4])[0]
        if magic not in MAGICS:
            sys.exit('%s: not a classic pcap (pcapng? convert with editcap -F nsecpcap)' % path)
        self.bo, self.mult = MAGICS[magic]
        _, _, _, _, self.snaplen, self.linktype = struct.unpack(self.bo + 'HHiIII', gh[4:])
        if self.linktype & 0xffff != LINKTYPE_ATSC_ALP:
            sys.exit('%s: linktype %d, not ATSC ALP (289)' % (path, self.linktype))
        self.count = 0

    def __iter__(self):
        hdr = struct.Struct(self.bo + 'IIII')
        while True:
            h = self.f.read(16)
            if not h:
                return
            if len(h) < 16:
                print('warning: %s: truncated record header at end, ignored' % self.path,
                      file=sys.stderr)
                return
            sec, frac, incl, orig = hdr.unpack(h)
            data = self.f.read(incl)
            if len(data) < incl:
                print('warning: %s: truncated record at end, ignored' % self.path,
                      file=sys.stderr)
                return
            self.count += 1
            yield sec * 1000000000 + frac * self.mult, orig, data


def l1_config(line):
    """The channel configuration in an L1 string - subframes and each PLP's
    ID, layer, size, modulation, code rate, FEC and interleaving mode -
    leaving out fields that change every frame (time offset, time of day,
    FEC block start). Uses atsc3-l1.py's L1-Detail parser. None if the
    string or the parser isn't available."""
    try:
        import importlib.util
        here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location('atsc3_l1', os.path.join(here, 'atsc3-l1.py'))
        l1 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(l1)
        raw = base64.b64decode(line, validate=True)
    except Exception:
        return None
    if len(raw) < 26:
        return None
    r = l1.Bits(raw[:25])
    b = {'version': r.u(3), 'mimo_sp_enc': r.u(1), 'lls_flg': r.u(1),
         'time_info_flg': r.u(2), 'return_ch_flg': r.u(1), 'papr': r.u(2),
         'frame_length_mode': r.u(1)}
    if b['frame_length_mode'] == 0:
        b['frame_length'] = r.u(10)
        r.u(13)
    else:
        r.u(16 + 7)
    for k, n in l1.L1B_FIELDS:
        b[k] = r.u(n)
    try:
        d = l1.parse_l1detail(raw[25:], b)
    except Exception:
        return None
    sfs = tuple((sf['fft_size'], sf['gi'], sf['num_ofdm_symbol'],
                 tuple((q['id'], q['layer'], q['size'], q.get('mod'), q.get('cod'),
                        q['fec_type'], q['ti_mode']) for q in sf['plps']))
                for sf in d['subframes'])
    return (b['frame_length_mode'], b.get('frame_length'), b['num_subframe'], sfs)


def txt_for(pcap):
    base, ext = os.path.splitext(pcap)
    return (base if ext in ('.pcap', '.pcapng') else pcap) + '.txt'


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__[__doc__.index('Modes'):])
    ap.add_argument('inputs', nargs='+', help='input pcaps; the first sets the start')
    ap.add_argument('-o', '--output', required=True, help='output pcap')
    m = ap.add_mutually_exclusive_group()
    m.add_argument('--append', dest='mode', action='store_const', const='append')
    m.add_argument('--interleave', dest='mode', action='store_const', const='interleave')
    m.add_argument('--align', dest='mode', action='store_const', const='align')
    ap.add_argument('--no-l1', action='store_true', help="don't copy the .txt L1 string")
    a = ap.parse_args()
    mode = a.mode or 'append'

    if os.path.abspath(a.output) in map(os.path.abspath, a.inputs):
        sys.exit('output must not be one of the inputs')
    caps = [Pcap(p) for p in a.inputs]

    # first timestamp of each file, for --align and the summary
    def first_ts(c):
        pos = c.f.tell()
        h = c.f.read(16)
        c.f.seek(pos)
        if len(h) < 16:
            return None
        sec, frac = struct.unpack(c.bo + 'II', h[:8])
        return sec * 1000000000 + frac * c.mult
    starts = [first_ts(c) for c in caps]
    if starts[0] is None:
        sys.exit('%s: no packets' % caps[0].path)

    def shifted(c, start):
        off = 0 if mode != 'align' or start is None else starts[0] - start
        for ts, orig, data in c:
            yield ts + off, orig, data

    streams = [shifted(c, s) for c, s in zip(caps, starts)]
    if mode == 'append':
        def chained():
            for s in streams:
                yield from s
        merged = chained()
    else:
        # heapq.merge is stable: equal timestamps keep input order
        merged = heapq.merge(*streams, key=lambda r: r[0])

    snaplen = max(262144, max(c.snaplen for c in caps))
    n = 0
    with open(a.output, 'wb') as out:
        out.write(struct.pack('<IHHiIII', 0xa1b23c4d, 2, 4, 0, 0, snaplen, LINKTYPE_ATSC_ALP))
        for ts, orig, data in merged:
            if ts < 0:
                ts = 0
            out.write(struct.pack('<IIII', ts // 1000000000, ts % 1000000000,
                                  len(data), orig))
            out.write(data)
            n += 1

    for c, s in zip(caps, starts):
        span = '' if s is None else ' starting %+.1f s' % ((s - starts[0]) / 1e9)
        print('%s: %d packets%s' % (c.path, c.count, span), file=sys.stderr)
    print('%s: %d packets (%s)' % (a.output, n, mode), file=sys.stderr)

    if not a.no_l1:
        txts = [txt_for(p) for p in a.inputs]
        have = [t for t in txts if os.path.exists(t)]
        if not have:
            print('note: no input .txt L1 string found; none written', file=sys.stderr)
        else:
            cfgs = {l1_config(open(t).read().strip()) for t in have}
            if len(cfgs) > 1:
                print('warning: the inputs\' L1 strings differ (configuration changed '
                      'between captures?); using %s' % have[0], file=sys.stderr)
            dst = txt_for(a.output)
            if os.path.abspath(dst) != os.path.abspath(have[0]):
                shutil.copyfile(have[0], dst)
                print('L1 string -> %s (from %s)' % (dst, have[0]), file=sys.stderr)


if __name__ == '__main__':
    main()
