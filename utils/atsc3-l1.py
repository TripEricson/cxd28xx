#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
atsc3-l1 - decode ATSC 3.0 bootstrap / L1-Basic / L1-Detail / PLP info,
read live from /dev/alpraw<N> (alp.ko) or from saved dumps.

  ./atsc3-l1.py                            # live, /dev/alpraw0
  ./atsc3-l1.py --dev /dev/alpraw1         # another tuner
  ./atsc3-l1.py --save dump/               # also save the raw dumps
  ./atsc3-l1.py --snapshot dump/atsc3_snapshot --l1detail dump/atsc3_l1detail
  ./atsc3-l1.py ... --json                 # machine-readable output
  ./atsc3-l1.py --hdhr                     # HDHomeRun-style base64 L1 string
  ./atsc3-l1.py --hdhr-out l1.txt          # ... written to a text file

No root needed with the udev rule (99-alpraw.rules: group video). Works
alongside a running capture: the L1 ioctl doesn't take over the device.

Run while atsc3-zap holds a lock. Register map: cxd2878_atsc3_regs.h.
"""
import argparse, base64, ctypes, errno, fcntl, json, os, struct, sys

DEFAULT_DEV = '/dev/alpraw0'

# alp_raw.h: struct alp_raw_l1 { u32 what; u32 len; u64 buf; }
# ALP_RAW_IOC_GET_L1 = _IOWR(0xA3, 0x40, struct alp_raw_l1)
ALP_RAW_L1_SNAPSHOT, ALP_RAW_L1_DETAIL = 1, 2
ALP_RAW_IOC_GET_L1 = (3 << 30) | (16 << 16) | (0xA3 << 8) | 0x40
L1_ERRORS = {errno.ENODATA: 'not tuned to ATSC 3.0', errno.EAGAIN: 'L1-Detail not decoded yet',
             errno.EOPNOTSUPP: "driver can't read L1", errno.ENODEV: 'tuner unplugged',
             errno.ENOTTY: "device doesn't support the L1 ioctl (old alp.ko?)"}


def l1_get(fd, what, size=16384):
    """Return bytes, or an error string."""
    buf = ctypes.create_string_buffer(size)
    req = bytearray(struct.pack('=IIQ', what, size, ctypes.addressof(buf)))
    try:
        fcntl.ioctl(fd, ALP_RAW_IOC_GET_L1, req)
    except OSError as e:
        return 'read failed: %s' % L1_ERRORS.get(e.errno, os.strerror(e.errno))
    n = struct.unpack_from('=I', req, 4)[0]
    return buf.raw[:n]

# ---------------------------------------------------------------- code tables
FFT = {0: '8K', 1: '16K', 2: '32K'}
GI = {1: 'GI1_192', 2: 'GI2_384', 3: 'GI3_512', 4: 'GI4_768', 5: 'GI5_1024', 6: 'GI6_1536',
      7: 'GI7_2048', 8: 'GI8_2432', 9: 'GI9_3072', 10: 'GI10_3648', 11: 'GI11_4096', 12: 'GI12_4864'}
SP = {i: 'SP%d_%d' % (d, b) for i, (d, b) in enumerate((x, y) for x in (3, 4, 6, 8, 12, 16, 24, 32) for y in (2, 4))}
PB_PILOT = {i: 'Dx=%d' % d for i, d in enumerate((3, 4, 6, 8, 12, 16, 24, 32))}
PAPR = {0: 'none', 1: 'TR', 2: 'ACE', 3: 'TR+ACE'}
MISO = {0: 'none', 1: 'MISO64', 2: 'MISO256'}
TIME_INFO = {0: 'none', 1: 'ms', 2: 'us', 3: 'ns'}
BS_BW = {0: '6 MHz', 1: '7 MHz', 2: '8 MHz', 3: '>8 MHz'}
PLP_FEC = {0: 'BCH+LDPC16K', 1: 'BCH+LDPC64K', 2: 'CRC+LDPC16K', 3: 'CRC+LDPC64K', 4: 'LDPC16K', 5: 'LDPC64K'}
PLP_MOD = {0: 'QPSK', 1: '16QAM', 2: '64QAM', 3: '256QAM', 4: '1024QAM', 5: '4096QAM'}
PLP_COD = {i: '%d/15' % (i + 2) for i in range(12)}
TI_MODE = {0: 'none', 1: 'CTI', 2: 'HTI'}
CTI_DEPTH = {0: '512', 1: '724', 2: '887/1254', 3: '1024/1448'}
SCRAMBLER = {0: 'PRBS'}
LDM_LEVEL = {i: '%.1f dB' % v for i, v in enumerate([x / 2 for x in range(0, 21)] + [float(x) for x in range(11, 26)])}

# demod-internal codes used only in the 90h:57h OFDM block
OFDM_BW = {0: 2, 1: 1, 2: 0}            # -> BS_BW code
OFDM_FFT = {1: 0, 4: 1, 5: 2}           # -> FFT code


def name(table, v):
    return table.get(v, 'reserved(%d)' % v)


# ---------------------------------------------------------------- snapshot
def parse_snapshot(blob):
    if blob[:4] != b'CXA3':
        raise ValueError('not a cxd2878 ATSC3 snapshot')
    regs, errs, pos = {}, [], 5
    while pos + 4 <= len(blob):
        bank, addr, n, st = blob[pos:pos + 4]
        data = blob[pos + 4:pos + 4 + n]
        if st:
            errs.append('%02Xh:%02Xh' % (bank, addr))
        else:
            for i, b in enumerate(data):
                regs[(bank, (addr + i) & 0xff)] = b
        pos += 4 + n
    return regs, errs


class Regs:
    def __init__(self, regs):
        self.r = regs

    def b(self, bank, addr):
        return self.r.get((bank, addr))

    def bits(self, bank, addr, hi, lo):
        return (self.r[(bank, addr)] >> lo) & ((1 << (hi - lo + 1)) - 1)

    def cat(self, bank, *parts):
        """parts: (addr, hi, lo) MSB first"""
        v = 0
        for addr, hi, lo in parts:
            v = (v << (hi - lo + 1)) | self.bits(bank, addr, hi, lo)
        return v


def decode_lock(R):
    sync = R.b(0x90, 0x10)
    alp = R.b(0x95, 0x40)
    l1 = R.b(0x93, 0x10)
    return {
        'seq_state': sync & 7, 'locked': (sync & 7) == 6 and bool(alp & 0x20) and not (sync & 0x10),
        'no_ofdm': bool(sync & 0x10), 'alp_lock_slots': alp & 0x0F,
        'alp_lock_all': bool(alp & 0x10), 'alp_lock_any': bool(alp & 0x20),
        'l1basic_valid': bool(l1 & 1), 'l1detail_valid': bool(l1 & 2),
    }


def decode_bootstrap(R):
    if not (R.b(0x90, 0xE6) & 1):
        return None
    return {'bw_diff': R.bits(0x90, 0xE0, 0, 0), 'system_bw': R.bits(0x90, 0xE1, 1, 0),
            'ea_wake_up': R.bits(0x90, 0xE2, 1, 0)}


def decode_ofdm(R):
    B = 0x90
    bw = R.bits(B, 0x57, 5, 4)
    pbf = R.bits(B, 0x5A, 7, 5)
    sff = R.bits(B, 0x5C, 7, 5)
    o = {
        'system_bw': OFDM_BW.get(bw), 'bs_num_symbol': R.bits(B, 0x57, 3, 0),
        'num_subframe': R.b(B, 0x58), 'l1b_fec_type': R.bits(B, 0x59, 7, 5),
        'papr': R.bits(B, 0x59, 4, 3), 'pb_num_symbol': R.bits(B, 0x59, 2, 0),
        'pb_fft_size': OFDM_FFT.get(pbf), 'pb_pilot': R.bits(B, 0x5A, 4, 0) >> 1 if R.bits(B, 0x5A, 4, 4) == 0 else None,
        'pb_reduced_carriers': R.bits(B, 0x5B, 6, 4), 'pb_gi': R.bits(B, 0x5B, 3, 0),
        'sf0_fft_size': OFDM_FFT.get(sff), 'sf0_sp': R.bits(B, 0x5C, 4, 0),
        'sf0_reduced_carriers': R.bits(B, 0x5D, 6, 4), 'sf0_gi': R.bits(B, 0x5D, 3, 0),
        'sf0_sp_boost': R.bits(B, 0x5E, 7, 5), 'sf0_sbs_first': R.bits(B, 0x5E, 4, 4),
        'sf0_sbs_last': R.bits(B, 0x5E, 3, 3), 'sf0_num_ofdm_symbol': R.cat(B, (0x5E, 2, 0), (0x5F, 7, 0)),
    }
    o['valid'] = None not in (o['system_bw'], o['pb_fft_size'], o['sf0_fft_size'], o['pb_pilot'])
    return o


def decode_l1basic(R):
    B = 0x93
    if not (R.b(B, 0x10) & 1):
        return None
    flm = R.bits(B, 0x61, 0, 0)
    o = {
        'version': R.bits(B, 0x60, 7, 5), 'mimo_sp_enc': R.bits(B, 0x60, 4, 4),
        'lls_flg': R.bits(B, 0x60, 3, 3), 'time_info_flg': R.bits(B, 0x60, 2, 1),
        'return_ch_flg': R.bits(B, 0x60, 0, 0), 'papr': R.bits(B, 0x61, 2, 1),
        'frame_length_mode': flm,
        'frame_length': R.cat(B, (0x62, 7, 0), (0x63, 7, 6)),
        'excess_smp_per_sym': R.cat(B, (0x63, 5, 0), (0x64, 6, 0)),
        'time_offset': R.cat(B, (0x65, 7, 0), (0x66, 7, 0)),
        'additional_smp': R.bits(B, 0x67, 6, 0),
        'num_subframe': R.b(B, 0x68), 'pb_num_symbol': R.bits(B, 0x69, 7, 5),
        'pb_reduced_carriers': R.bits(B, 0x69, 4, 2), 'l1d_content_tag': R.bits(B, 0x69, 1, 0),
        'l1d_size': R.cat(B, (0x6A, 7, 0), (0x6B, 7, 3)), 'l1d_fec_type': R.bits(B, 0x6B, 2, 0),
        'l1d_add_parity_mode': R.bits(B, 0x6C, 7, 6),
        'l1d_total_cells': R.cat(B, (0x6C, 5, 0), (0x6D, 7, 0), (0x6E, 7, 3)),
        'sf0_mimo': R.bits(B, 0x6E, 2, 2), 'sf0_miso': R.bits(B, 0x6E, 1, 0),
        'sf0_fft_size': R.bits(B, 0x6F, 7, 6), 'sf0_reduced_carriers': R.bits(B, 0x6F, 5, 3),
        'sf0_gi': R.cat(B, (0x6F, 2, 0), (0x70, 7, 7)),
        'sf0_num_ofdm_symbol': R.cat(B, (0x70, 6, 0), (0x71, 7, 4)),
        'sf0_sp': R.cat(B, (0x71, 3, 0), (0x72, 5, 5)), 'sf0_sp_boost': R.bits(B, 0x72, 4, 2),
        'sf0_sbs_first': R.bits(B, 0x72, 1, 1), 'sf0_sbs_last': R.bits(B, 0x72, 0, 0),
    }
    return o


L1B_FIELDS = [  # A/322 Table 9.2 order, after the frame_length_mode branch
    ('num_subframe', 8), ('pb_num_symbol', 3), ('pb_reduced_carriers', 3), ('l1d_content_tag', 2),
    ('l1d_size', 13), ('l1d_fec_type', 3), ('l1d_add_parity_mode', 2), ('l1d_total_cells', 19),
    ('sf0_mimo', 1), ('sf0_miso', 2), ('sf0_fft_size', 2), ('sf0_reduced_carriers', 3), ('sf0_gi', 4),
    ('sf0_num_ofdm_symbol', 11), ('sf0_sp', 5), ('sf0_sp_boost', 3), ('sf0_sbs_first', 1), ('sf0_sbs_last', 1)]


def l1basic_raw(R, b):
    """Rebuild the 25-byte A/322 L1-Basic bitstream (200 bits) from the register
    view. L1B_crc is written as zero, as the HDHomeRun does."""
    f = [(b['version'], 3), (b['mimo_sp_enc'], 1), (b['lls_flg'], 1), (b['time_info_flg'], 2),
         (b['return_ch_flg'], 1), (b['papr'], 2), (b['frame_length_mode'], 1)]
    if b['frame_length_mode'] == 0:
        f += [(b['frame_length'], 10), (b['excess_smp_per_sym'], 13)]
    else:
        f += [(b['time_offset'], 16), (b['additional_smp'], 7)]
    f += [(b[k], n) for k, n in L1B_FIELDS]
    f += [(R.b(0x93, a), 8) for a in range(0x73, 0x79)]     # L1B_reserved, 48 bits
    f += [(0, 32)]                                             # L1B_crc
    v = 0
    for val, n in f:
        v = (v << n) | (val & ((1 << n) - 1))
    return v.to_bytes(25, 'big')


def decode_plp_list(R):
    B = 0x93
    if not (R.b(B, 0x10) & 2) or not (R.b(B, 0x9D) & 1):
        return None
    if R.b(B, 0x9E) & 1:
        return {'changed': True}

    def bit(base, i):
        return (R.b(B, base + i // 8) >> (7 - i % 8)) & 1
    plps = [{'id': i, 'lls_flg': bit(0xA8, i), 'layer': bit(0xB0, i)} for i in range(64) if bit(0xA0, i)]
    return {'num_plp': R.bits(B, 0x9F, 6, 0), 'plps': plps}


def decode_slots(R):
    B = 0x93
    if not (R.b(B, 0x10) & 2) or not (R.b(B, 0x9D) & 1):
        return None
    err = R.b(B, 0x84) & 1
    slots = []
    for n in range(4):
        idr = R.b(B, 0x80 + n)
        sh = 4 if n % 2 == 0 else 0
        reg = n // 2
        slots.append({
            'slot': n, 'plp_id': idr & 0x3F, 'selected': bool(idr & 0x80),
            'valid': bool(idr & 0x80) and not err,
            'fec_type': (R.b(B, 0x90 + reg) >> sh) & 0xF,
            'mod': (R.b(B, 0x92 + reg) >> sh) & 0xF,
            'cod': (R.b(B, 0x94 + reg) >> sh) & 0xF,
        })
    return {'plp_error': bool(err), 'slots': slots}


# ---------------------------------------------------------------- L1-Detail (A/322 Table 9.8)
class Bits:
    def __init__(self, data):
        self.d, self.p = data, 0

    def u(self, n):
        v = 0
        for _ in range(n):
            if self.p >= len(self.d) * 8:
                raise EOFError('L1-Detail truncated at bit %d' % self.p)
            v = (v << 1) | ((self.d[self.p >> 3] >> (7 - (self.p & 7))) & 1)
            self.p += 1
        return v


def crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc


def parse_l1detail(data, l1b):
    """l1b: dict from decode_l1basic()"""
    r = Bits(data)
    out = {'version': r.u(4), 'num_rf': r.u(3), 'bonded_bsid': [], 'subframes': []}
    for _ in range(out['num_rf']):
        out['bonded_bsid'].append(r.u(16))
        r.u(3)
    tif = l1b['time_info_flg']
    if tif:
        out['time_sec'] = r.u(32)
        out['time_msec'] = r.u(10)
        if tif >= 2:
            out['time_usec'] = r.u(10)
        if tif >= 3:
            out['time_nsec'] = r.u(10)
    for i in range(l1b['num_subframe'] + 1):
        sf = {'index': i}
        if i == 0:
            for k in ('mimo', 'miso', 'fft_size', 'reduced_carriers', 'gi', 'num_ofdm_symbol',
                      'sp', 'sp_boost', 'sbs_first', 'sbs_last'):
                sf[k] = l1b['sf0_' + k]
        else:
            sf['mimo'] = r.u(1); sf['miso'] = r.u(2); sf['fft_size'] = r.u(2)
            sf['reduced_carriers'] = r.u(3); sf['gi'] = r.u(4); sf['num_ofdm_symbol'] = r.u(11)
            sf['sp'] = r.u(5); sf['sp_boost'] = r.u(3); sf['sbs_first'] = r.u(1); sf['sbs_last'] = r.u(1)
        if l1b['num_subframe'] > 0:
            sf['subframe_mux'] = r.u(1)
        sf['freq_interleaver'] = r.u(1)
        if sf['sbs_first'] or sf['sbs_last']:
            sf['sbs_null_cells'] = r.u(13)
        sf['num_plp'] = r.u(6) + 1
        sf['plps'] = []
        for _ in range(sf['num_plp']):
            p = {'id': r.u(6), 'lls_flg': r.u(1), 'layer': r.u(2), 'start': r.u(24), 'size': r.u(24),
                 'scrambler_type': r.u(2), 'fec_type': r.u(4)}
            if p['fec_type'] <= 5:
                p['mod'] = r.u(4)
                p['cod'] = r.u(4)
            p['ti_mode'] = r.u(2)
            if p['ti_mode'] == 0:
                p['fec_block_start'] = r.u(15)
            elif p['ti_mode'] == 1:
                p['cti_fec_block_start'] = r.u(22)
            if out['num_rf'] > 0:
                p['num_ch_bonded'] = r.u(3)
                if p['num_ch_bonded'] > 0:
                    p['ch_bonding_format'] = r.u(2)
                    p['bonded_rf_id'] = [r.u(3) for _ in range(p['num_ch_bonded'] + 1)]
            if sf['mimo']:
                p['mimo_stream_combine'] = r.u(1)
                p['mimo_iq_interleave'] = r.u(1)
                p['mimo_ph'] = r.u(1)
            if p['layer'] == 0:
                p['plp_type'] = r.u(1)
                if p['plp_type'] == 1:
                    p['num_subslice'] = r.u(14) + 1
                    p['subslice_interval'] = r.u(24)
                # modulation defaults to QPSK when fec_type carries no mod/cod field
                if p['ti_mode'] in (1, 2) and p.get('mod', 0) == 0:
                    p['ti_ext_interleave'] = r.u(1)
                if p['ti_mode'] == 1:
                    p['cti_depth'] = r.u(3)
                    p['cti_start_row'] = r.u(11)
                elif p['ti_mode'] == 2:
                    p['hti_inter_subframe'] = r.u(1)
                    p['hti_num_ti_blocks'] = r.u(4) + 1
                    p['hti_num_fec_block_max'] = r.u(12) + 1
                    if p['hti_inter_subframe'] == 0:
                        p['hti_num_fec_block'] = [r.u(12) + 1]
                    else:
                        p['hti_num_fec_block'] = [r.u(12) + 1 for _ in range(p['hti_num_ti_blocks'])]
                    p['hti_cell_interleave'] = r.u(1)
            else:
                p['ldm_inj_level'] = r.u(5)
            sf['plps'].append(p)
        out['subframes'].append(sf)
    if out['version'] >= 1:
        out['bsid'] = r.u(16)
    out['reserved_bits'] = len(data) * 8 - 32 - r.p
    # The demod only releases L1-Detail after its own BCH/LDPC decode succeeds
    # (93h:10h[1]). The trailing L1D_crc field does not match CRC-32/MPEG-2 or
    # other common variants over these bytes, and the vendor code never checks
    # it, so it is reported but not verified.
    out['crc_field'] = '%08x' % int.from_bytes(data[-4:], 'big')
    return out


# ---------------------------------------------------------------- output
def fmt_text(res):
    L = []
    lk = res['lock']
    L.append('Lock: %s  (seq_state=%d, ALP any=%d all=%d slots=%s, L1B valid=%d, L1D valid=%d)' % (
        'YES' if lk['locked'] else 'no', lk['seq_state'], lk['alp_lock_any'], lk['alp_lock_all'],
        format(lk['alp_lock_slots'], '04b'), lk['l1basic_valid'], lk['l1detail_valid']))
    if res.get('snapshot_errors'):
        L.append('Register read errors: ' + ', '.join(res['snapshot_errors']))
    bs = res.get('bootstrap')
    if bs:
        L.append('\nBootstrap: bandwidth %s, bw_diff=%d, ea_wake_up=%d' % (
            name(BS_BW, bs['system_bw']), bs['bw_diff'], bs['ea_wake_up']))
    o = res.get('ofdm')
    if o and o['valid']:
        L.append('\nPreamble / OFDM (demod view):')
        L.append('  bootstrap symbols %d, subframes %d, L1-Basic FEC mode %d, PAPR %s' % (
            o['bs_num_symbol'], o['num_subframe'] + 1, o['l1b_fec_type'] + 1, name(PAPR, o['papr'])))
        L.append('  preamble: %d symbols, FFT %s, %s, GI %s, reduced carriers %d' % (
            o['pb_num_symbol'] + 1, name(FFT, o['pb_fft_size']), name(PB_PILOT, o['pb_pilot']),
            name(GI, o['pb_gi']), o['pb_reduced_carriers']))
    b = res.get('l1basic')
    if b:
        L.append('\nL1-Basic (v%d):' % b['version'])
        L.append('  LLS present=%d, time info=%s, return channel=%d, MIMO SP enc=%d, PAPR %s' % (
            b['lls_flg'], name(TIME_INFO, b['time_info_flg']), b['return_ch_flg'], b['mimo_sp_enc'], name(PAPR, b['papr'])))
        if b['frame_length_mode'] == 0:
            L.append('  time-aligned frame: length %d ms, excess samples/symbol %d' % (b['frame_length'] * 5, b['excess_smp_per_sym']))
        else:
            L.append('  symbol-aligned frame: time offset %d, additional samples %d' % (b['time_offset'], b['additional_smp']))
        L.append('  subframes %d, preamble symbols %d, preamble reduced carriers %d' % (
            b['num_subframe'] + 1, b['pb_num_symbol'] + 1, b['pb_reduced_carriers']))
        L.append('  L1-Detail: %d bytes, FEC mode %d, add. parity %d, %d cells, content tag %d' % (
            b['l1d_size'], b['l1d_fec_type'] + 1, b['l1d_add_parity_mode'], b['l1d_total_cells'], b['l1d_content_tag']))
        L.append('  subframe 0: FFT %s, GI %s, %s boost %d, %d symbols, reduced carriers %d, MIMO %d, MISO %s, SBS first/last %d/%d' % (
            name(FFT, b['sf0_fft_size']), name(GI, b['sf0_gi']), name(SP, b['sf0_sp']), b['sf0_sp_boost'],
            b['sf0_num_ofdm_symbol'] + 1, b['sf0_reduced_carriers'], b['sf0_mimo'], name(MISO, b['sf0_miso']),
            b['sf0_sbs_first'], b['sf0_sbs_last']))
    pl = res.get('plp_list')
    if pl:
        if pl.get('changed'):
            L.append('\nPLP list: changed since last read (retry)')
        else:
            L.append('\nPLP list (%d): %s' % (pl['num_plp'], ', '.join(
                '%d%s%s' % (p['id'], ' [LLS]' if p['lls_flg'] else '', ' [enhanced]' if p['layer'] else '') for p in pl['plps'])))
    sl = res.get('slots')
    if sl:
        L.append('\nDecoding slots%s:' % (' (PLP ERROR)' if sl['plp_error'] else ''))
        for s in sl['slots']:
            if s['selected']:
                L.append('  slot %d: PLP %d  %s %s %s' % (s['slot'], s['plp_id'], name(PLP_FEC, s['fec_type']),
                                                         name(PLP_MOD, s['mod']), name(PLP_COD, s['cod'])))
    d = res.get('l1detail')
    if isinstance(d, str):
        L.append('\nL1-Detail: ' + d)
    elif d:
        L.append('\nL1-Detail (v%d, %d bytes, %d reserved bits):' % (d['version'], res['l1basic']['l1d_size'], d['reserved_bits']))
        if 'bsid' in d:
            L.append('  BSID 0x%04x' % d['bsid'])
        if d['num_rf']:
            L.append('  channel bonding: %d other RF, BSIDs %s' % (d['num_rf'], d['bonded_bsid']))
        if 'time_sec' in d:
            t = '%d s + %d ms' % (d['time_sec'], d['time_msec'])
            if 'time_usec' in d:
                t += ' + %d us' % d['time_usec']
            if 'time_nsec' in d:
                t += ' + %d ns' % d['time_nsec']
            L.append('  PTP time: ' + t)
        for sf in d['subframes']:
            L.append('  subframe %d: FFT %s, GI %s, %s, %d symbols, %s freq interleaver, %d PLP(s)' % (
                sf['index'], name(FFT, sf['fft_size']), name(GI, sf['gi']), name(SP, sf['sp']), sf['num_ofdm_symbol'] + 1,
                'with' if sf['freq_interleaver'] else 'no', sf['num_plp']))
            for p in sf['plps']:
                mc = '%s %s %s' % (name(PLP_FEC, p['fec_type']), name(PLP_MOD, p.get('mod', -1)), name(PLP_COD, p.get('cod', -1))) \
                    if 'mod' in p else name(PLP_FEC, p['fec_type'])
                ti = name(TI_MODE, p['ti_mode'])
                if 'cti_depth' in p:
                    ti += ' depth %s' % name(CTI_DEPTH, p['cti_depth'])
                elif 'hti_num_ti_blocks' in p:
                    ti += ' %d TI blocks' % p['hti_num_ti_blocks']
                extra = ' LDM inj %s' % name(LDM_LEVEL, p['ldm_inj_level']) if p['layer'] else ''
                L.append('    PLP %2d%s: %s, TI %s, cells %d@%d, layer %d%s' % (
                    p['id'], ' [LLS]' if p['lls_flg'] else '', mc, ti, p['size'], p['start'], p['layer'], extra))
    return '\n'.join(L)


def analyze(snap, l1d):
    regs, errs = parse_snapshot(snap)
    R = Regs(regs)
    res = {'lock': decode_lock(R), 'snapshot_errors': errs}
    res['bootstrap'] = decode_bootstrap(R)
    res['ofdm'] = decode_ofdm(R) if res['lock']['locked'] else None
    res['l1basic'] = decode_l1basic(R)
    res['l1basic_raw'] = l1basic_raw(R, res['l1basic']).hex() if res['l1basic'] else None
    res['plp_list'] = decode_plp_list(R)
    res['slots'] = decode_slots(R)
    if l1d is not None and res['l1basic']:
        if isinstance(l1d, str):
            res['l1detail'] = l1d
        elif len(l1d) != res['l1basic']['l1d_size']:
            res['l1detail'] = 'size %d does not match L1-Basic (%d)' % (len(l1d), res['l1basic']['l1d_size'])
        else:
            try:
                res['l1detail'] = parse_l1detail(l1d, res['l1basic'])
            except EOFError as e:
                res['l1detail'] = str(e)
    return res


def read_file(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except OSError as e:
        return 'read failed: %s' % (os.strerror(e.errno) if e.errno else e)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dev', default=DEFAULT_DEV, help='raw ALP device (default %(default)s)')
    ap.add_argument('--snapshot', help='offline: saved atsc3_snapshot file')
    ap.add_argument('--l1detail', help='offline: saved atsc3_l1detail file')
    ap.add_argument('--save', metavar='DIR', help='save raw dumps to DIR')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--hdhr', action='store_true',
                    help='print only the HDHomeRun-style L1 string: base64(L1-Basic 25 bytes + L1-Detail)')
    ap.add_argument('--hdhr-out', metavar='FILE', help='write the HDHomeRun-style L1 string to FILE')
    a = ap.parse_args()

    if a.snapshot:
        snap = read_file(a.snapshot)
        l1d = read_file(a.l1detail) if a.l1detail else None
    else:
        try:
            fd = os.open(a.dev, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            hint = {errno.ENOENT: ' (patched alp.ko loaded?)',
                    errno.EACCES: ' (udev rule installed? in group video?)'}.get(e.errno, '')
            sys.exit('%s: %s%s' % (a.dev, e.strerror, hint))
        try:
            snap = l1_get(fd, ALP_RAW_L1_SNAPSHOT, 1024)
            l1d = l1_get(fd, ALP_RAW_L1_DETAIL)
        finally:
            os.close(fd)
    if isinstance(snap, str):
        sys.exit('atsc3_snapshot: %s (tuned to ATSC 3.0? run atsc3-zap first)' % snap)
    if a.save:
        os.makedirs(a.save, exist_ok=True)
        open(os.path.join(a.save, 'atsc3_snapshot'), 'wb').write(snap)
        if isinstance(l1d, bytes):
            open(os.path.join(a.save, 'atsc3_l1detail'), 'wb').write(l1d)
    try:
        res = analyze(snap, l1d)
    except (ValueError, KeyError) as e:
        sys.exit('cannot decode snapshot: %s' % e)
    if a.hdhr or a.hdhr_out:
        if not res['l1basic']:
            sys.exit('no L1-Basic yet (not locked?)')
        if not isinstance(res.get('l1detail'), dict):
            sys.exit('no L1-Detail: %s' % (res.get('l1detail') or l1d))
        line = base64.b64encode(bytes.fromhex(res['l1basic_raw']) + l1d).decode()
        if a.hdhr_out:
            with open(a.hdhr_out, 'w') as f:
                f.write(line + '\n')
        if a.hdhr:
            print(line)
            return
    print(json.dumps(res, indent=1) if a.json else fmt_text(res))


if __name__ == '__main__':
    main()
