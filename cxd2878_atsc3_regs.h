/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Sony CXD2878 / CXD6801 ATSC 3.0 signalling register map
 *
 * Derived by black-box emulation of the ATSC 3.0 monitor routines in the
 * Zenview/GTMedia HDTV Mate vendor library (liba3_phy_sony.so, aarch64,
 * BuildID 7d4b23ae7278f21db3970aa0e02a8891bad13aeb): each routine was run
 * against a simulated register file, every bank/register access was logged,
 * and every input bit was flipped individually to see which output field it
 * drives. Only register addresses, bit positions and code values are recorded
 * here. Not yet verified on live hardware -- treat as a strong draft.
 *
 * Conventions (all registers are on the SLV-T I2C slave):
 *   - Bank select:  write bank number to sub-address 0x00.
 *   - Freeze:       write 0x01 <- 1 before a multi-register snapshot and
 *                   0x01 <- 0 after it, so all fields come from the same frame.
 *                   (Every monitor below does this except PLP list / L1-Detail.)
 *   - Bit notation: REG[hi:lo]. Multi-byte fields are big-endian across
 *                   consecutive registers, MSB first, e.g. 62h[7:0]|63h[7:6]
 *                   is a 10-bit value whose top 8 bits are in 62h.
 *   - Unless a code table is given, the value is the raw ATSC A/321 / A/322
 *     field value.
 */
#ifndef CXD2878_ATSC3_REGS_H
#define CXD2878_ATSC3_REGS_H

#define CXD_ATSC3_REG_BANK		0x00
#define CXD_ATSC3_REG_FREEZE		0x01

/* ------------------------------------------------------------------------
 * Lock / readiness
 * ------------------------------------------------------------------------ */

/* Bank 90h */
#define CXD_ATSC3_BANK_DEMOD		0x90
#define CXD_ATSC3_SYNC			0x10	/* [2:0] seq state, 6 = locked; [4] no ATSC3 OFDM (unlock detected) */

/* Bank 95h */
#define CXD_ATSC3_BANK_ALP		0x95
#define CXD_ATSC3_ALPLOCK		0x40	/* [3:0] per-PLP-slot ALP lock, [4] all slots locked, [5] any slot locked */

/* Bank 93h status */
#define CXD_ATSC3_BANK_L1		0x93
#define CXD_ATSC3_L1_STATUS		0x10	/* [0] L1-Basic valid; [1] L1-Detail / PLP info valid */

/* ------------------------------------------------------------------------
 * Bootstrap (A/321)                                    bank 90h, freeze
 *   Valid only when 90h:E6h[0] == 1, then read 3 bytes at 90h:E0h.
 * ------------------------------------------------------------------------ */
#define CXD_ATSC3_BS_VALID		0xE6	/* [0] */
#define CXD_ATSC3_BS_BASE		0xE0	/* 3 bytes */
/*   bw_diff                 E0h[0]
 *   system_bandwidth        E1h[1:0]   0=6 MHz 1=7 MHz 2=8 MHz 3=>8 MHz
 *   ea_wake_up              E2h[1:0]
 */

/* ------------------------------------------------------------------------
 * Bootstrap/preamble/first-subframe OFDM parameters      bank 90h, freeze
 *   Requires demod lock (90h:10h[2:0]==6 and ALP lock). Read 9 bytes at 57h.
 *   Some fields here use demod-internal codes (tables below), not A/322 codes.
 * ------------------------------------------------------------------------ */
#define CXD_ATSC3_OFDM_BASE		0x57	/* 9 bytes: 57h..5Fh */
/*   system_bw               57h[5:4]   0=8 MHz 1=7 MHz 2=6 MHz (3 invalid)   <-- note: reversed vs bootstrap
 *   bs_num_symbol           57h[3:0]   bootstrap symbols
 *   num_subframe            58h[7:0]
 *   l1b_fec_type            59h[7:5]   0..6 = L1-Basic FEC mode 1..7
 *   papr                    59h[4:3]   0 none, 1 TR, 2 ACE, 3 TR+ACE
 *   pb_num_symbol           59h[2:0]   preamble symbols
 *   pb_fft_size             5Ah[7:5]   1=8K 4=16K 5=32K (others invalid)
 *   pb_pilot (Dx)           5Ah[3:1]   0..7 = Dx 3,4,6,8,12,16,24,32  (5Ah[4] must be 0; 5Ah[0] ignored)
 *   pb_reduced_carriers     5Bh[6:4]
 *   pb_guard_interval       5Bh[3:0]   A/322 GI code (1=GI1_192 ... 12=GI12_4864)
 *   sf0_fft_size            5Ch[7:5]   1=8K 4=16K 5=32K
 *   sf0_scattered_pilot     5Ch[4:0]   A/322 SP code (0=SP3_2 ... 15=SP32_4)
 *   sf0_reduced_carriers    5Dh[6:4]
 *   sf0_guard_interval      5Dh[3:0]
 *   sf0_sp_boost            5Eh[7:5]
 *   sf0_sbs_first           5Eh[4]
 *   sf0_sbs_last            5Eh[3]
 *   sf0_num_ofdm_symbols    5Eh[2:0] | 5Fh[7:0]   (11 bits)
 */

/* ------------------------------------------------------------------------
 * L1-Basic (A/322 Table 9.2)                             bank 93h, freeze
 *   Valid when 93h:10h[0] == 1. Read 29 bytes at 60h (60h..7Ch).
 *   Layout is Sony's repacking, NOT the raw A/322 bitstream: both
 *   frame_length_mode branches have fixed slots, and there are pad bits.
 * ------------------------------------------------------------------------ */
#define CXD_ATSC3_L1B_BASE		0x60	/* 29 bytes */
/*   version                 60h[7:5]
 *   mimo_sp_encoding        60h[4]
 *   lls_flag                60h[3]
 *   time_info_flag          60h[2:1]   0 none, 1 ms, 2 us, 3 ns
 *   return_channel_flag     60h[0]
 *   papr_reduction          61h[2:1]
 *   frame_length_mode       61h[0]
 *   -- frame_length_mode == 0 (time-aligned):
 *   frame_length            62h[7:0] | 63h[7:6]   (10 bits)
 *   excess_samples_per_sym  63h[5:0] | 64h[6:0]   (13 bits)
 *   -- frame_length_mode == 1 (symbol-aligned):
 *   time_offset             65h[7:0] | 66h[7:0]   (16 bits)
 *   additional_samples      67h[6:0]
 *   --
 *   num_subframes           68h[7:0]   (value + 1 subframes)
 *   preamble_num_symbols    69h[7:5]
 *   preamble_reduced_carr.  69h[4:2]
 *   L1_Detail_content_tag   69h[1:0]
 *   L1_Detail_size_bytes    6Ah[7:0] | 6Bh[7:3]   (13 bits)
 *   L1_Detail_fec_type      6Bh[2:0]
 *   L1_Detail_add_parity    6Ch[7:6]
 *   L1_Detail_total_cells   6Ch[5:0] | 6Dh[7:0] | 6Eh[7:3]   (19 bits)
 *   first_sub_mimo          6Eh[2]
 *   first_sub_miso          6Eh[1:0]
 *   first_sub_fft_size      6Fh[7:6]   0=8K 1=16K 2=32K
 *   first_sub_reduced_carr. 6Fh[5:3]
 *   first_sub_guard_interval 6Fh[2:0] | 70h[7]    (4 bits)
 *   first_sub_num_ofdm_sym  70h[6:0] | 71h[7:4]   (11 bits)
 *   first_sub_sp_pattern    71h[3:0] | 72h[5]     (5 bits; 72h[7:6] unused)
 *   first_sub_sp_boost      72h[4:2]
 *   first_sub_sbs_first     72h[1]
 *   first_sub_sbs_last      72h[0]
 *   reserved                from 73h   (A/322 reserved bits, passed through; rest of the 29 bytes unused)
 */

/* ------------------------------------------------------------------------
 * PLP list (all PLPs in the frame)                     bank 93h, no freeze
 *   Read 93h:10h; require [1]. Then read 36 bytes at 9Dh (9Dh..C0h).
 * ------------------------------------------------------------------------ */
#define CXD_ATSC3_PLPLIST_BASE		0x9D	/* 36 bytes */
#define CXD_ATSC3_PLPINFO_UPD		0x9C	/* write 1 to acknowledge a PLP-info change */
/*   ready                   9Dh[0]     must be 1
 *   changed                 9Eh[0]     if 1: write 93h:9Ch <- 1 and retry later
 *   num_plp                 9Fh[6:0]   0..64; equals popcount of the bitmap below
 *   plp_present bitmap      A0h..A7h   64 bits, MSB first: A0h[7] = PLP 0 ... A7h[0] = PLP 63
 *   plp_lls_flag bitmap     A8h..AFh   same bit order
 *   plp_layer bitmap        B0h..B7h   same bit order (1 = LDM enhanced layer)
 *   B8h..C0h                read but not used in single-RF mode (likely channel-bonding info)
 */

/* ------------------------------------------------------------------------
 * Selected PLP slots (the up-to-4 PLPs the demod is decoding)     bank 93h
 *   These are the same registers cxd28xx already writes for PLP selection.
 *   Valid only when 93h:10h[1] == 1 and 93h:9Dh[0] == 1.
 * ------------------------------------------------------------------------ */
#define CXD_ATSC3_PLP_ID(n)		(0x80 + (n))	/* n=0..3: [7] slot valid, [5:0] PLP ID */
#define CXD_ATSC3_PLP_ERROR		0x84	/* [0] PLP error (selected PLP not present) */
#define CXD_ATSC3_PLP_FEC01		0x90	/* [7:4] slot0 FEC type, [3:0] slot1 */
#define CXD_ATSC3_PLP_FEC23		0x91	/* [7:4] slot2, [3:0] slot3 */
#define CXD_ATSC3_PLP_MOD01		0x92	/* [7:4] slot0 modulation, [3:0] slot1 */
#define CXD_ATSC3_PLP_MOD23		0x93
#define CXD_ATSC3_PLP_COD01		0x94	/* [7:4] slot0 code rate, [3:0] slot1 */
#define CXD_ATSC3_PLP_COD23		0x95
/*   A slot's ModCod is meaningful when PLP_ID(n)[7] == 1 and PLP_ERROR[0] == 0.
 *   FEC type:  0 BCH+LDPC16K, 1 BCH+LDPC64K, 2 CRC+16K, 3 CRC+64K, 4 LDPC16K, 5 LDPC64K
 *   Mod:       0 QPSK, 1 16QAM, 2 64QAM, 3 256QAM, 4 1024QAM, 5 4096QAM
 *   Code rate: 0..11 = 2/15 .. 13/15
 */

/* ------------------------------------------------------------------------
 * L1-Detail, raw (A/322 Table 9.8)                     no freeze, polled
 *
 *   The demod hands back the decoded L1-Detail payload as raw bytes. The
 *   bytes are the A/322 L1-Detail bitstream starting at bit 0 (L1D_version)
 *   and ending with the 32-bit L1D_crc, so any A/322 parser can decode them.
 *   Its length equals L1-Basic L1_Detail_size_bytes.
 *
 *   Sequence:
 *    1. bank 93h; read 10h; require [1] (else not ready).
 *    2. poll 93h:E1h every 10 ms until [7] == 1   (timeout 100 ms).
 *    3. write 93h:E0h <- 1                        (request/hold L1-Detail)
 *    4. read L1-Basic (above), for L1_Detail_size_bytes and time_info_flag.
 *    5. poll 93h:E1h every 10 ms (timeout 100 ms):
 *         [6] == 1  -> error, abort
 *         [5] == 1  -> data ready, continue
 *    6. read 2 bytes at 93h:E1h: size = (E1h[4:0] << 8) | E2h   (bytes)
 *    7. for page = 0, offset = 0; remaining > 0; page++:
 *         bank 93h; write E3h <- page
 *         n = min(remaining, 240)
 *         bank 92h; read n bytes starting at 92h:10h into buf[offset]
 *         offset += n; remaining -= n
 *    8. bank 93h; write E0h <- 0                  (release; do this on every exit path)
 * ------------------------------------------------------------------------ */
#define CXD_ATSC3_L1D_CTRL		0xE0	/* bank 93h: 1 = request, 0 = release */
#define CXD_ATSC3_L1D_STAT		0xE1	/* bank 93h: [7] idle/ready for request, [6] error, [5] data ready, [4:0] size[12:8] */
#define CXD_ATSC3_L1D_SIZE_LO		0xE2	/* bank 93h: size[7:0] */
#define CXD_ATSC3_L1D_PAGE		0xE3	/* bank 93h: 240-byte page index */
#define CXD_ATSC3_BANK_L1D_DATA		0x92
#define CXD_ATSC3_L1D_DATA		0x10	/* bank 92h: page window, up to 240 bytes */
#define CXD_ATSC3_L1D_PAGE_SIZE		240

/* ------------------------------------------------------------------------
 * Signal-quality monitors: register locations only (formulas not derived;
 * cxd28xx already implements SNR and BCH error rate from the same registers).
 * ------------------------------------------------------------------------ */
/*   SNR                     90h:28h x3, 90h:58h x1        (freeze; requires lock)
 *   Carrier offset          90h:4Ch x4, 90h:F3h x1        (freeze; requires lock)
 *   Spectrum inversion      90h:F3h x1                    (freeze; requires lock)
 *   Sampling offset         90h:52h x5, 90h:9Fh x5        (freeze; requires lock)
 *   IF AGC                  90h:26h x2
 *   Pre-LDPC BER            94h:30h x18, 93h:90h x2       (freeze; per-slot, uses FEC type)
 *   Pre-BCH BER             94h:4Ah x19, 93h:90h x2, 93h:94h x2   (freeze; uses FEC type + code rate)
 *   Post-BCH FER            94h:5Dh x8, 94h:4Dh/51h/55h/59h x1, 94h:4Ah x2   (freeze)
 *   BB packet error count   94h:94h x12                   (no freeze)
 */

#endif /* CXD2878_ATSC3_REGS_H */
