/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * alp-capture - capture raw ATSC 3.0 ALP packets from /dev/alpraw%d into a
 * pcap file with LINKTYPE_ATSC_ALP (289), one ALP packet per record,
 * nanosecond timestamps (pcap magic a1b23c4d).
 *
 * /dev/alpraw%d (alp.ko) delivers every complete top-level ALP packet
 * unmodified, including link-layer signalling (LMT) that alp%d drops, and
 * serves L1 signalling through an ioctl. With the udev rule (99-alpraw.rules)
 * it belongs to group "video", like /dev/dvb, so no root is needed.
 *
 * Usage: alp-capture -w <file.pcap|-> [-c channel | -F freq_hz] [-p plps]
 *                    [-a adapter] [-n frontend] [-i /dev/alpraw0] [-N count]
 *                    [-t seconds] [-q] [-l l1.txt | -L] [-x packets]
 *
 *   With -c or -F, tunes ATSC 3.0 itself (like atsc3-zap), waits for lock and
 *   holds the frontend for the whole capture. Without them, tune separately
 *   first; signal is then read through a read-only frontend handle.
 *   Signal level, SNR and pre-BCH BER are reported every second.
 *
 *   At start, the HDHomeRun-style L1 string - base64(L1-Basic 25 bytes +
 *   L1-Detail) - is written next to the pcap (capture.pcap -> capture.txt).
 *
 *   The tuner's USB bridge passes data on only in whole transfers, 64 KB by
 *   default, so a PLP of a few kbit/s decoded on its own could take minutes
 *   to arrive. From the decoded PLPs' capacity in L1-Detail, alp-capture asks
 *   for transfers that fill in about half a second when 64 KB would be
 *   slower; -x sets the size by hand. The request ends with the capture.
 *
 * Build: make utils   (passes -DSYS_ATSC3=35 when the system headers lack it)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/dvb/frontend.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "../alp_raw.h"

#define LINKTYPE_ATSC_ALP 289
#define PCAP_SNAPLEN 262144	/* header value, as libpcap/tcpdump write it */
#define PCAP_MAGIC_NSEC 0xa1b23c4d	/* nanosecond-resolution classic pcap */
#define REC_BUF (sizeof(struct alp_raw_hdr) + 65536)

#ifndef NO_STREAM_ID_FILTER
#define NO_STREAM_ID_FILTER (~0U)
#endif

static volatile sig_atomic_t running = 1;

static void on_signal(int sig)
{
	(void)sig;
	running = 0;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"Usage: %s -w <file.pcap|-> [-c channel | -F freq_hz] [-p plps] [options]\n"
		"  -w FILE   output pcap (LINKTYPE_ATSC_ALP); '-' for stdout\n"
		"  -c CH     tune US RF channel CH (2-36) first and hold the tuner\n"
		"  -F HZ     tune ATSC 3.0 to HZ first (e.g. 569000000) and hold the tuner\n"
		"  -p LIST   PLP IDs to decode, up to 4 (e.g. 0,1,16); default auto:\n"
		"            every PLP the channel carries, up to 4, LLS first\n"
		"  -a N      DVB adapter (default 0)\n"
		"  -n N      frontend (default 0)\n"
		"  -T SEC    lock timeout with -c/-F (default 10)\n"
		"  -i DEV    raw ALP device (default /dev/alpraw<adapter>)\n"
		"  -N N      stop after N packets\n"
		"  -t SEC    stop after SEC seconds\n"
		"  -q        no periodic status or signal lines on stderr\n"
		"  -l FILE   write the HDHR-style L1 string to FILE\n"
		"            (default: the pcap name with .txt; required with -w -)\n"
		"  -L        don't write the L1 string\n"
		"  -x N      USB transfer size in TS packets (4-348, 0 = driver default);\n"
		"            default: sized from the selected PLPs' bitrate, so a\n"
		"            low-bitrate PLP on its own still arrives promptly\n", p);
}

static int write_all(FILE *f, const void *p, size_t n)
{
	return fwrite(p, 1, n, f) == n ? 0 : -1;
}

/* ── Tuning (same DVBv5 sequence as atsc3-zap) ─────────────────────── */

/*
 * US 6 MHz RF channel -> centre frequency (Hz), post-repack plan (TV ends at
 * channel 36). Returns 0 for a channel outside it.
 */
static unsigned us_channel_hz(long ch)
{
	if (ch >= 2 && ch <= 4)
		return (57 + 6 * (ch - 2)) * 1000000u;
	if (ch >= 5 && ch <= 6)
		return (79 + 6 * (ch - 5)) * 1000000u;
	if (ch >= 7 && ch <= 13)
		return (177 + 6 * (ch - 7)) * 1000000u;
	if (ch >= 14 && ch <= 36)
		return (473 + 6 * (ch - 14)) * 1000000u;
	return 0;
}

static int parse_plps(char *list, unsigned *stream_id)
{
	char *tok = strtok(list, ",");
	int slot = 0;

	*stream_id = 0;
	while (tok && slot < 4) {
		char *end;
		unsigned long id = strtoul(tok, &end, 0);

		if (*end || id > 63) {
			fprintf(stderr, "PLP ID must be 0-63: %s\n", tok);
			return -1;
		}
		*stream_id |= (unsigned)id << (slot * 8);
		slot++;
		tok = strtok(NULL, ",");
	}
	if (!slot || tok) {
		fprintf(stderr, slot ? "at most 4 PLPs\n" : "no PLP IDs given\n");
		return -1;
	}
	for (; slot < 4; slot++)
		*stream_id |= 0xFFu << (slot * 8);
	return 0;
}

static int tune_atsc3(int fe, unsigned freq, unsigned stream_id)
{
	struct dtv_property p[5];
	struct dtv_properties cmd = { .props = p };
	int n = 0;

	memset(p, 0, sizeof(p));
	p[0].cmd = DTV_CLEAR;
	cmd.num = 1;
	if (ioctl(fe, FE_SET_PROPERTY, &cmd) < 0)
		return -1;

	memset(p, 0, sizeof(p));
	p[n].cmd = DTV_DELIVERY_SYSTEM;	p[n++].u.data = SYS_ATSC3;
	p[n].cmd = DTV_FREQUENCY;	p[n++].u.data = freq;
	p[n].cmd = DTV_BANDWIDTH_HZ;	p[n++].u.data = 6000000;
	if (stream_id != NO_STREAM_ID_FILTER) {
		p[n].cmd = DTV_STREAM_ID;
		p[n++].u.data = stream_id;
	}
	p[n++].cmd = DTV_TUNE;
	cmd.num = n;
	return ioctl(fe, FE_SET_PROPERTY, &cmd);
}

static int fe_locked(int fe)
{
	enum fe_status st = 0;

	if (ioctl(fe, FE_READ_STATUS, &st) < 0)
		return -1;
	return !!(st & FE_HAS_LOCK);
}

struct sigstats {
	int have_sig, have_snr, have_ber;
	double sig_dbm, snr_db, ber;
};

/*
 * Read signal stats from the frontend cache (refreshed by read_status,
 * which fe_locked() triggers). cxd2878 puts the pre-BCH BER of the PLP in
 * slot 0, scaled by 1e9, in the post-error counter.
 */
static void get_stats(int fe, struct sigstats *st)
{
	struct dtv_property p[3];
	struct dtv_properties cmd = { .num = 3, .props = p };

	memset(st, 0, sizeof(*st));
	memset(p, 0, sizeof(p));
	p[0].cmd = DTV_STAT_SIGNAL_STRENGTH;
	p[1].cmd = DTV_STAT_CNR;
	p[2].cmd = DTV_STAT_POST_ERROR_BIT_COUNT;
	if (ioctl(fe, FE_GET_PROPERTY, &cmd) < 0)
		return;
	if (p[0].u.st.len && p[0].u.st.stat[0].scale == FE_SCALE_DECIBEL) {
		st->have_sig = 1;
		st->sig_dbm = p[0].u.st.stat[0].svalue / 1000.0;
	}
	if (p[1].u.st.len && p[1].u.st.stat[0].scale == FE_SCALE_DECIBEL) {
		st->have_snr = 1;
		st->snr_db = p[1].u.st.stat[0].svalue / 1000.0;
	}
	if (p[2].u.st.len && p[2].u.st.stat[0].scale == FE_SCALE_COUNTER) {
		st->have_ber = 1;
		st->ber = p[2].u.st.stat[0].uvalue / 1e9;
	}
}

static void print_stats(const char *prefix, const struct sigstats *st)
{
	fprintf(stderr, "%s", prefix);
	if (st->have_sig)
		fprintf(stderr, "  signal %6.1f dBm", st->sig_dbm);
	if (st->have_snr)
		fprintf(stderr, "  SNR %5.1f dB", st->snr_db);
	if (st->have_ber)
		fprintf(stderr, "  pre-BCH BER %.1e", st->ber);
	fprintf(stderr, "\n");
}

static void print_signal(int fe)
{
	struct sigstats st;

	get_stats(fe, &st);
	print_stats("locked:", &st);
}

/* ── L1 signalling through the /dev/alpraw ioctl ───────────────────── */

/* Returns bytes, or -errno. */
static int l1_get(int fd, unsigned what, uint8_t *buf, unsigned len)
{
	struct alp_raw_l1 req = { .what = what, .len = len,
				  .buf = (uint64_t)(uintptr_t)buf };

	if (ioctl(fd, ALP_RAW_IOC_GET_L1, &req) < 0)
		return -errno;
	return req.len;
}

static const char *l1_why(int err)
{
	switch (err) {
	case -ENODATA:	return "not tuned to ATSC 3.0";
	case -EAGAIN:	return "L1 not decoded yet";
	case -EOPNOTSUPP: return "driver can't read L1 (old cxd2878/bridge module?)";
	case -ENODEV:	return "tuner unplugged";
	case -ENOTTY:	return "device doesn't support the L1 ioctl (old alp.ko?)";
	case -EINVAL:	return "malformed register snapshot";
	default:	return strerror(-err);
	}
}

struct bitw {
	uint8_t *p;
	int pos;
};

static void put_bits(struct bitw *w, unsigned v, int n)
{
	while (n--) {
		if ((v >> n) & 1)
			w->p[w->pos >> 3] |= 0x80 >> (w->pos & 7);
		w->pos++;
	}
}

static char *b64(const uint8_t *in, size_t n)
{
	static const char t[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char *out = malloc((n + 2) / 3 * 4 + 1), *o = out;
	size_t i;

	if (!out)
		return NULL;
	for (i = 0; i + 2 < n; i += 3) {
		*o++ = t[in[i] >> 2];
		*o++ = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
		*o++ = t[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
		*o++ = t[in[i + 2] & 63];
	}
	if (n - i == 1) {
		*o++ = t[in[i] >> 2];
		*o++ = t[(in[i] & 3) << 4];
		*o++ = '=';
		*o++ = '=';
	} else if (n - i == 2) {
		*o++ = t[in[i] >> 2];
		*o++ = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
		*o++ = t[(in[i + 1] & 15) << 2];
		*o++ = '=';
	}
	*o = 0;
	return out;
}

/* Read bank 93h from the register snapshot. Returns 0 or -errno. */
static int read_bank93(int fd, uint8_t *r93, uint8_t *have)
{
	uint8_t snap[1024];
	int sn, pos, i;

	sn = l1_get(fd, ALP_RAW_L1_SNAPSHOT, snap, sizeof(snap));
	if (sn < 0)
		return sn;
	if (sn < 5 || memcmp(snap, "CXA3", 4))
		return -EINVAL;
	memset(have, 0, 256);
	for (pos = 5; pos + 4 <= sn; pos += 4 + snap[pos + 2]) {
		uint8_t bank = snap[pos], addr = snap[pos + 1], n = snap[pos + 2];

		if (bank != 0x93 || snap[pos + 3] || pos + 4 + n > sn)
			continue;
		for (i = 0; i < n; i++) {
			r93[(uint8_t)(addr + i)] = snap[pos + 4 + i];
			have[(uint8_t)(addr + i)] = 1;
		}
	}
	return 0;
}

/*
 * Build base64(L1-Basic + L1-Detail). L1-Basic is rebuilt from the demod's
 * register view (bank 93h, 60h-78h; see cxd2878_atsc3_regs.h). Sony's layout
 * is the A/322 bitstream with gaps, so the 200 bits are these register bit
 * ranges in order, plus a zero L1B_crc as the HDHomeRun writes it.
 * Returns a malloc'd string, or NULL with *why set.
 */
static char *build_l1_string(int fd, const char **why)
{
	static uint8_t l1d[8192 + 25];
	uint8_t r93[256], have[256];
	int dn, i, ret;
	unsigned l1d_size;
	struct bitw w;

	ret = read_bank93(fd, r93, have);
	if (ret) {
		*why = l1_why(ret);
		return NULL;
	}
	if (!have[0x10] || !have[0x78]) {
		*why = "snapshot incomplete";
		return NULL;
	}
	if ((r93[0x10] & 3) != 3) {
		*why = "L1 not decoded yet";
		return NULL;
	}

	memset(l1d, 0, 25);
	w.p = l1d;
	w.pos = 0;
	put_bits(&w, r93[0x60], 8);			/* version .. return_channel */
	put_bits(&w, r93[0x61] & 7, 3);			/* papr, frame_length_mode */
	if (!(r93[0x61] & 1)) {
		put_bits(&w, r93[0x62], 8);		/* frame_length */
		put_bits(&w, r93[0x63] >> 6, 2);
		put_bits(&w, r93[0x63] & 0x3F, 6);	/* excess_samples_per_symbol */
		put_bits(&w, r93[0x64] & 0x7F, 7);
	} else {
		put_bits(&w, r93[0x65], 8);		/* time_offset */
		put_bits(&w, r93[0x66], 8);
		put_bits(&w, r93[0x67] & 0x7F, 7);	/* additional_samples */
	}
	for (i = 0x68; i <= 0x71; i++)			/* num_subframes .. first_sub_sp */
		put_bits(&w, r93[i], 8);
	put_bits(&w, r93[0x72] & 0x3F, 6);		/* sp lsb, boost, sbs_first/last */
	for (i = 0x73; i <= 0x78; i++)			/* L1B_reserved */
		put_bits(&w, r93[i], 8);
	put_bits(&w, 0, 32);				/* L1B_crc */
	if (w.pos != 200) {
		*why = "internal error building L1-Basic";
		return NULL;
	}

	l1d_size = (r93[0x6A] << 5) | (r93[0x6B] >> 3);
	dn = l1_get(fd, ALP_RAW_L1_DETAIL, l1d + 25, sizeof(l1d) - 25);
	if (dn < 0) {
		*why = l1_why(dn);
		return NULL;
	}
	if ((unsigned)dn != l1d_size) {
		*why = "L1-Detail size does not match L1-Basic";
		return NULL;
	}
	return b64(l1d, 25 + dn);
}


static void default_l1_name(const char *pcap, char *out, size_t len)
{
	const char *dot = strrchr(pcap, '.'), *slash = strrchr(pcap, '/');

	if (dot && (!slash || dot > slash) &&
	    (!strcmp(dot, ".pcap") || !strcmp(dot, ".pcapng")))
		snprintf(out, len, "%.*s.txt", (int)(dot - pcap), pcap);
	else
		snprintf(out, len, "%s.txt", pcap);
}

/* Retry for a few seconds: L1-Detail may not be decoded right after tuning. */
static void write_l1_string(int fd, const char *path, int quiet)
{
	const char *why = "";
	char *line = NULL;
	FILE *f;
	int tries;

	for (tries = 0; tries < 10 && running && !line; tries++) {
		if (tries)
			usleep(500000);
		line = build_l1_string(fd, &why);
	}
	if (!line) {
		fprintf(stderr, "warning: no L1 string written: %s\n", why);
		return;
	}
	f = fopen(path, "w");
	if (!f || fprintf(f, "%s\n", line) < 0 || fclose(f)) {
		perror(path);
	} else if (!quiet) {
		fprintf(stderr, "L1 string -> %s\n", path);
	}
	free(line);
}

/*
 * After lock, keep polling the frontend (the driver's auto-PLP selection
 * runs from read_status once L1-Detail is decoded) until L1 is decoded,
 * then report which PLPs the demod is decoding.
 */
static void settle_and_report(int fe, int raw, int quiet)
{
	uint8_t r93[256], have[256];
	int i, ok = 0;

	for (i = 0; i < 50 && running && !ok; i++) {
		fe_locked(fe);
		ok = !read_bank93(raw, r93, have) && have[0x10] && (r93[0x10] & 3) == 3;
		if (!ok)
			usleep(100000);
	}
	if (!ok)
		return;
	/* one more poll so auto-PLP can program the slots, then read them */
	fe_locked(fe);
	usleep(300000);
	fe_locked(fe);
	if (quiet || read_bank93(raw, r93, have) || !have[0x83])
		return;
	fprintf(stderr, "decoding PLPs:");
	for (i = 0; i < 4; i++)
		if (r93[0x80 + i] & 0x80)
			fprintf(stderr, " %d", r93[0x80 + i] & 0x3F);
	fprintf(stderr, "\n");
}

/* ── Transfer size from the selected PLPs' bitrate ─────────────────────── */

struct bitr {
	const uint8_t *d;
	unsigned len, pos;	/* bytes, bits */
	int err;
};

static unsigned get_bits(struct bitr *r, int n)
{
	unsigned v = 0;

	while (n--) {
		if (r->pos >= r->len * 8) {
			r->err = 1;
			return 0;
		}
		v = (v << 1) | ((r->d[r->pos >> 3] >> (7 - (r->pos & 7))) & 1);
		r->pos++;
	}
	return v;
}

/*
 * Capacity, in bits per second, of the PLPs whose IDs are set in want[]
 * (A/322 L1-Detail; layout as in atsc3-l1.py): cells per frame x bits per
 * cell x code rate, over the frame duration. FEC overhead beyond the code
 * rate is ignored - this only has to be right to within a factor of two.
 * Returns 0 if L1 can't be parsed.
 */
static double plp_bitrate(const uint8_t *r93, const uint8_t *l1d, unsigned dlen,
			  const int *want)
{
	static const unsigned gi_samples[13] = { 0, 192, 384, 512, 768, 1024, 1536,
						 2048, 2432, 3072, 3648, 4096, 4864 };
	struct bitr r = { l1d, dlen, 0, 0 };
	unsigned num_rf, tif, nsf, i, j, k;
	double bits = 0, samples = 0, frame_s;
	unsigned sf0_fft = r93[0x6F] >> 6;
	unsigned sf0_gi = ((r93[0x6F] & 7) << 1) | (r93[0x70] >> 7);

	get_bits(&r, 4);				/* version */
	num_rf = get_bits(&r, 3);
	for (i = 0; i < num_rf; i++)
		get_bits(&r, 19);			/* bonded bsid, reserved */
	tif = (r93[0x60] >> 1) & 3;
	if (tif)
		get_bits(&r, 42 + 10 * (tif - 1));	/* sec, msec [, usec [, nsec]] */
	nsf = r93[0x68] + 1;

	/* bootstrap (4 symbols, 2 ms) and preamble, approximated with
	 * subframe 0's FFT size and guard interval */
	samples = 0.002 * 6.912e6 +
		  ((r93[0x69] >> 5) + 1) * ((8192u << sf0_fft) + gi_samples[sf0_gi % 13]);

	for (i = 0; i < nsf && !r.err; i++) {
		unsigned mimo, fft, gi, nsym, sbs_first, sbs_last, nplp;

		if (i == 0) {
			mimo = (r93[0x6E] >> 2) & 1;
			fft = sf0_fft;
			gi = sf0_gi;
			nsym = ((r93[0x70] & 0x7F) << 4) | (r93[0x71] >> 4);
			sbs_first = (r93[0x72] >> 1) & 1;
			sbs_last = r93[0x72] & 1;
		} else {
			mimo = get_bits(&r, 1);
			get_bits(&r, 2);		/* miso */
			fft = get_bits(&r, 2);
			get_bits(&r, 3);		/* reduced carriers */
			gi = get_bits(&r, 4);
			nsym = get_bits(&r, 11);
			get_bits(&r, 5 + 3);		/* sp, sp boost */
			sbs_first = get_bits(&r, 1);
			sbs_last = get_bits(&r, 1);
		}
		if (fft > 2)
			return 0;
		samples += (nsym + 1.0) * ((8192u << fft) + gi_samples[gi % 13]);
		if (nsf > 1)
			get_bits(&r, 1);		/* subframe mux */
		get_bits(&r, 1);			/* frequency interleaver */
		if (sbs_first || sbs_last)
			get_bits(&r, 13);
		nplp = get_bits(&r, 6) + 1;
		for (j = 0; j < nplp && !r.err; j++) {
			unsigned id = get_bits(&r, 6), layer, size, fec, mod = 0, cod = 0, ti;

			get_bits(&r, 1);		/* lls */
			layer = get_bits(&r, 2);
			get_bits(&r, 24);		/* start */
			size = get_bits(&r, 24);
			get_bits(&r, 2);		/* scrambler */
			fec = get_bits(&r, 4);
			if (fec <= 5) {
				mod = get_bits(&r, 4);
				cod = get_bits(&r, 4);
			}
			ti = get_bits(&r, 2);
			if (ti == 0)
				get_bits(&r, 15);
			else if (ti == 1)
				get_bits(&r, 22);
			if (num_rf > 0) {
				unsigned nb = get_bits(&r, 3);

				if (nb) {
					get_bits(&r, 2);
					get_bits(&r, 3 * (nb + 1));
				}
			}
			if (mimo)
				get_bits(&r, 3);
			if (layer == 0) {
				if (get_bits(&r, 1))	/* plp_type: subslices */
					get_bits(&r, 14 + 24);
				if ((ti == 1 || ti == 2) && mod == 0)
					get_bits(&r, 1);
				if (ti == 1) {
					get_bits(&r, 3 + 11);
				} else if (ti == 2) {
					unsigned inter = get_bits(&r, 1);
					unsigned nti = get_bits(&r, 4) + 1;

					get_bits(&r, 12);
					for (k = 0; k < (inter ? nti : 1); k++)
						get_bits(&r, 12);
					get_bits(&r, 1);
				}
			} else {
				get_bits(&r, 5);	/* LDM injection level */
			}
			if (want[id] && mod <= 5 && cod <= 11)
				bits += (double)size * (2 * mod + 2) * (cod + 2) / 15.0;
		}
	}
	if (r.err || samples <= 0)
		return 0;
	if (!(r93[0x61] & 1))				/* time-aligned: 5 ms units */
		frame_s = ((r93[0x62] << 2) | (r93[0x63] >> 6)) * 0.005;
	else
		frame_s = samples / 6.912e6;
	return frame_s > 0 ? bits / frame_s : 0;
}

#define XFER_MAX_PACKETS 348	/* the bridge's default, 64 KB */
#define XFER_FILL_SEC	0.5	/* aim for a transfer at least this often */

/*
 * The tuner's USB bridge hands data over only in whole transfers (64 KB by
 * default). A PLP of a few kbit/s decoded on its own would then take minutes
 * to arrive, so ask for transfers that fill in about XFER_FILL_SEC at the
 * selected PLPs' rate. Must run before the first read()/poll() starts the
 * stream. manual: -x value (-1 = automatic, 0 = driver default).
 */
static void set_transfer_size(int raw, int manual, int quiet)
{
	static uint8_t l1d[8192];
	uint8_t r93[256], have[256];
	int want[64] = { 0 }, i, n, any = 0;
	double bps = 0;
	uint32_t packets, eff;

	if (manual >= 0) {
		packets = manual;
	} else {
		const char *why = NULL;
		int tries;

		/* L1 can lag the PLP selection; retry briefly */
		for (tries = 0; tries < 10 && running; tries++) {
			if (tries)
				usleep(300000);
			n = read_bank93(raw, r93, have);
			if (n) {
				why = l1_why(n);
				continue;
			}
			if (!have[0x83] || !have[0x72]) {
				why = "register snapshot incomplete";
				continue;
			}
			if ((r93[0x10] & 3) != 3) {
				why = "L1 not decoded yet";
				continue;
			}
			memset(want, 0, sizeof(want));
			any = 0;
			for (i = 0; i < 4; i++)
				if (r93[0x80 + i] & 0x80) {
					want[r93[0x80 + i] & 0x3F] = 1;
					any = 1;
				}
			if (!any) {
				why = "no PLPs selected yet";
				continue;
			}
			n = l1_get(raw, ALP_RAW_L1_DETAIL, l1d, sizeof(l1d));
			if (n <= 0) {
				why = n ? l1_why(n) : "empty L1-Detail";
				continue;
			}
			bps = plp_bitrate(r93, l1d, n, want);
			why = bps > 0 ? NULL : "can't parse L1-Detail";
			break;
		}
		if (why) {
			fprintf(stderr, "note: USB transfer size left at default (%s);"
				" use -x for a low-bitrate PLP\n", why);
			return;
		}
		packets = (uint32_t)(bps / 8 * XFER_FILL_SEC / 188) + 1;
		if (packets >= XFER_MAX_PACKETS) {
			if (!quiet)
				fprintf(stderr, "PLP capacity ~%.1f Mbit/s: default USB transfers\n",
					bps / 1e6);
			return;
		}
	}

	eff = packets;
	if (ioctl(raw, ALP_RAW_IOC_SET_XFER, &eff) < 0) {
		if (errno == ENOTTY || errno == EOPNOTSUPP)
			fprintf(stderr, "warning: driver can't change the USB transfer size%s;\n"
				"  low-bitrate PLPs may take minutes to arrive\n",
				errno == ENOTTY ? " (old alp.ko?)" : "");
		else
			fprintf(stderr, "warning: setting the USB transfer size: %s\n",
				strerror(errno));
		return;
	}
	if (quiet)
		return;
	if (manual >= 0)
		fprintf(stderr, "USB transfers: %u TS packets%s\n", eff,
			manual ? "" : " (driver default)");
	else
		fprintf(stderr, "low-bitrate PLPs (~%.0f kbit/s capacity): USB transfers"
			" of %u TS packets (one every ~%.1f s)\n",
			bps / 1000, eff, eff * 188 * 8 / bps);
}

static const char *raw_err(int err)
{
	switch (err) {
	case EBUSY:	return "already being read by another program";
	case ENODEV:	return "tuner unplugged";
	default:	return strerror(err);
	}
}

int main(int argc, char **argv)
{
	const char *devname = NULL, *outname = NULL, *l1name = NULL;
	char l1buf[512], devbuf[64];
	int no_l1 = 0, rc = 1, quiet = 0, opt, raw = -1;
	unsigned freq = 0, stream_id = NO_STREAM_ID_FILTER;
	int adapter = 0, frontend = 0, lock_timeout = 10, fe = -1, locked = 1, xfer = -1;
	long channel = 0, tick = 0, max_count = 0, max_secs = 0;
	unsigned long long pkts = 0, bytes = 0, types[8] = { 0 }, drops = 0;
	struct timespec start, now, last_fe = { 0, 0 };
	FILE *out = NULL;
	static uint8_t buf[REC_BUF];

	while ((opt = getopt(argc, argv, "w:i:c:N:t:ql:LF:p:a:n:T:x:h")) != -1) {
		switch (opt) {
		case 'w': outname = optarg; break;
		case 'i': devname = optarg; break;
		case 'N': max_count = strtol(optarg, NULL, 0); break;
		case 't': max_secs = strtol(optarg, NULL, 0); break;
		case 'q': quiet = 1; break;
		case 'l': l1name = optarg; break;
		case 'L': no_l1 = 1; break;
		case 'c':
			if (freq) {
				fprintf(stderr, "use -c or -F, not both\n");
				return 1;
			}
			channel = strtol(optarg, NULL, 10);
			freq = us_channel_hz(channel);
			if (!freq) {
				fprintf(stderr, "channel must be 2-36 (US); use -F for a frequency\n");
				return 1;
			}
			break;
		case 'F':
			if (channel) {
				fprintf(stderr, "use -c or -F, not both\n");
				return 1;
			}
			freq = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			if (parse_plps(optarg, &stream_id))
				return 1;
			break;
		case 'a': adapter = atoi(optarg); break;
		case 'n': frontend = atoi(optarg); break;
		case 'T': lock_timeout = atoi(optarg); break;
		case 'x': xfer = atoi(optarg); break;
		default: usage(argv[0]); return opt == 'h' ? 0 : 1;
		}
	}
	if (!outname) {
		usage(argv[0]);
		return 1;
	}
	if (stream_id != NO_STREAM_ID_FILTER && !freq) {
		fprintf(stderr, "-p needs -c or -F (PLPs are chosen when tuning)\n");
		return 1;
	}
	if (!no_l1 && !l1name) {
		if (!strcmp(outname, "-")) {
			no_l1 = 1;
		} else {
			default_l1_name(outname, l1buf, sizeof(l1buf));
			l1name = l1buf;
		}
	}
	if (!devname) {
		snprintf(devbuf, sizeof(devbuf), "/dev/alpraw%d", adapter);
		devname = devbuf;
	} else if (devname[0] != '/') {
		snprintf(devbuf, sizeof(devbuf), "/dev/%s", devname);
		devname = devbuf;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, on_signal);

	/* Opening doesn't start the feed; the first read() or poll() does. */
	raw = open(devname, O_RDONLY | O_NONBLOCK);
	if (raw < 0) {
		fprintf(stderr, "%s: %s%s\n", devname, strerror(errno),
			errno == ENOENT ? " (patched alp.ko loaded?)" :
			errno == EACCES ? " (udev rule installed? in group video?)" : "");
		return 1;
	}

	if (freq) {
		char fe_path[64];
		int waited;

		snprintf(fe_path, sizeof(fe_path), "/dev/dvb/adapter%d/frontend%d",
			 adapter, frontend);
		fe = open(fe_path, O_RDWR);
		if (fe < 0) {
			fprintf(stderr, "%s: %s%s\n", fe_path, strerror(errno),
				errno == EBUSY ? " (another app is using the tuner)" : "");
			goto close_raw;
		}
		if (tune_atsc3(fe, freq, stream_id) < 0) {
			perror("tune (FE_SET_PROPERTY)");
			goto close_fe;
		}
		if (channel)
			fprintf(stderr, "tuning channel %ld (%u Hz), %s ...\n", channel, freq,
				stream_id == NO_STREAM_ID_FILTER ? "auto PLP" : "selected PLPs");
		else
			fprintf(stderr, "tuning %u Hz, %s ...\n", freq,
				stream_id == NO_STREAM_ID_FILTER ? "auto PLP" : "selected PLPs");
		for (waited = 0; running && fe_locked(fe) != 1; waited++) {
			if (waited >= lock_timeout * 10) {
				fprintf(stderr, "no lock after %d s\n", lock_timeout);
				goto close_fe;
			}
			usleep(100000);
		}
		if (!running)
			goto close_fe;
		print_signal(fe);
		settle_and_report(fe, raw, quiet);
	} else {
		/* Someone else tuned: a read-only handle can still read status
		 * and stats without disturbing their tuning. */
		char fe_path[64];

		snprintf(fe_path, sizeof(fe_path), "/dev/dvb/adapter%d/frontend%d",
			 adapter, frontend);
		fe = open(fe_path, O_RDONLY | O_NONBLOCK);
		if (fe < 0 && !quiet)
			fprintf(stderr, "note: %s: %s; no signal reports\n",
				fe_path, strerror(errno));
	}

	if (!no_l1)
		write_l1_string(raw, l1name, quiet);
	/* before the first poll() below starts the stream */
	set_transfer_size(raw, xfer, quiet);

	out = strcmp(outname, "-") ? fopen(outname, "wb") : stdout;
	if (!out) {
		perror(outname);
		goto close_fe;
	}
	{
		struct {
			uint32_t magic;
			uint16_t vmaj, vmin;
			int32_t thiszone;
			uint32_t sigfigs, snaplen, network;
		} __attribute__((packed)) gh = { PCAP_MAGIC_NSEC, 2, 4, 0, 0, PCAP_SNAPLEN, LINKTYPE_ATSC_ALP };
		if (write_all(out, &gh, sizeof(gh))) {
			perror("write");
			goto close_out;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	if (!quiet)
		fprintf(stderr, "capturing %s -> %s (Ctrl-C to stop)\n", devname, outname);

	while (running) {
		struct pollfd pfd = { .fd = raw, .events = POLLIN };
		struct alp_raw_hdr *h = (struct alp_raw_hdr *)buf;
		const uint8_t *pkt = buf + sizeof(*h);
		ssize_t n;
		int pr;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (max_secs && now.tv_sec - start.tv_sec >= max_secs)
			break;
		/*
		 * Once a second: poll the frontend (this also runs the driver's
		 * status/auto-PLP logic while we hold it) and report signal;
		 * every 5 s also report capture progress.
		 */
		if (now.tv_sec - start.tv_sec > tick) {
			char pfx[32];

			tick = now.tv_sec - start.tv_sec;
			snprintf(pfx, sizeof(pfx), "[%5lds]", tick);
			if (fe >= 0 && now.tv_sec != last_fe.tv_sec) {
				int l = fe_locked(fe);

				if (l == 0) {
					fprintf(stderr, "%s  NO LOCK\n", pfx);
				} else if (l == 1) {
					struct sigstats st;

					if (!locked)
						fprintf(stderr, "%s  lock regained\n", pfx);
					if (!quiet) {
						get_stats(fe, &st);
						print_stats(pfx, &st);
					}
				}
				locked = (l != 0);
				last_fe = now;
			}
			if (!quiet && tick % 5 == 0)
				fprintf(stderr, "%s  %llu packets, %.1f MB, signalling %llu%s\n",
					pfx, pkts, bytes / 1e6, types[4],
					drops ? " (some dropped: disk too slow?)" : "");
		}

		/* poll() also claims the device as reader and starts the feed */
		pr = poll(&pfd, 1, 200);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}
		if (!pr)
			continue;
		if ((pfd.revents & (POLLERR | POLLHUP)) && !(pfd.revents & POLLIN)) {
			n = read(raw, buf, sizeof(buf));	/* get the reason */
			fprintf(stderr, "%s: %s\n", devname,
				n < 0 ? raw_err(errno) : "error");
			break;
		}
		/* drain what is queued */
		while (running) {
			n = read(raw, buf, sizeof(buf));
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR)
					break;
				fprintf(stderr, "%s: %s\n", devname, raw_err(errno));
				running = 0;
				break;
			}
			if ((size_t)n < sizeof(*h) || h->len != n - sizeof(*h))
				continue;	/* not a whole record: shouldn't happen */
			drops += h->drops;
			{
				uint32_t rh[4] = { (uint32_t)(h->tstamp_ns / 1000000000ull),
						   (uint32_t)(h->tstamp_ns % 1000000000ull),
						   h->len, h->len };
				if (write_all(out, rh, sizeof(rh)) || write_all(out, pkt, h->len)) {
					perror("write");
					running = 0;
					break;
				}
			}
			pkts++;
			bytes += h->len;
			if (h->len)
				types[(pkt[0] >> 5) & 7]++;
			if (max_count && (long)pkts >= max_count) {
				running = 0;
				break;
			}
		}
	}

	fprintf(stderr,
		"%llu ALP packets, %llu bytes; dropped %llu (reader too slow)\n"
		"  by type: IPv4 %llu, compressed IP %llu, signalling %llu, ext %llu, TS %llu, other %llu\n",
		pkts, bytes, drops, types[0], types[2], types[4], types[6], types[7],
		types[1] + types[3] + types[5]);
	rc = 0;
close_out:
	fflush(out);
	if (out != stdout)
		fclose(out);
close_fe:
	if (fe >= 0)
		close(fe);	/* frontend sleeps once the last user closes it */
close_raw:
	close(raw);		/* stops the feed if nothing else needs it */
	return rc;
}
