/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 * \brief Convenient Signal Processing routines
 */

#ifndef _DSP_H
#define _DSP_H

#define DSP_FEATURE_SILENCE_SUPPRESS	(1 << 0)
#define DSP_FEATURE_BUSY_DETECT		(1 << 1)
#define DSP_FEATURE_DIGIT_DETECT	(1 << 3)
#define DSP_FEATURE_FAX_DETECT		(1 << 4)
#define DSP_FEATURE_ENERGYLEVEL		(1 << 5)

#define	DSP_DIGITMODE_DTMF			0				/*!< Detect DTMF digits */
#define DSP_DIGITMODE_MF			1				/*!< Detect MF digits */

#define DSP_DIGITMODE_NOQUELCH		(1 << 8)		/*!< Do not quelch DTMF from in-band */
#define DSP_DIGITMODE_MUTECONF		(1 << 9)		/*!< Mute conference */
#define DSP_DIGITMODE_MUTEMAX		(1 << 10)		/*!< Delay audio by a frame to try to extra quelch */
#define DSP_DIGITMODE_RELAXDTMF		(1 << 11)		/*!< "Radio" mode (relaxed DTMF) */

#define DSP_PROGRESS_TALK		(1 << 16)		/*!< Enable talk detection */
#define DSP_PROGRESS_RINGING		(1 << 17)		/*!< Enable calling tone detection */
#define DSP_PROGRESS_BUSY		(1 << 18)		/*!< Enable busy tone detection */
#define DSP_PROGRESS_CONGESTION		(1 << 19)		/*!< Enable congestion tone detection */
#define DSP_FEATURE_CALL_PROGRESS	(DSP_PROGRESS_TALK | DSP_PROGRESS_RINGING | DSP_PROGRESS_BUSY | DSP_PROGRESS_CONGESTION)
#define DSP_FEATURE_WAITDIALTONE	(1 << 20)		/*!< Enable dial tone detection */

#define DSP_FAXMODE_DETECT_CNG		(1 << 0)
#define DSP_FAXMODE_DETECT_CED		(1 << 1)
#define DSP_FAXMODE_DETECT_SQUELCH	(1 << 2)
#define DSP_FAXMODE_DETECT_ALL	(DSP_FAXMODE_DETECT_CNG | DSP_FAXMODE_DETECT_CED)

#define DSP_TONE_STATE_SILENCE  0
#define DSP_TONE_STATE_RINGING  1
#define DSP_TONE_STATE_DIALTONE 2
#define DSP_TONE_STATE_TALKING  3
#define DSP_TONE_STATE_BUSY     4
#define DSP_TONE_STATE_SPECIAL1	5
#define DSP_TONE_STATE_SPECIAL2 6
#define DSP_TONE_STATE_SPECIAL3 7
#define DSP_TONE_STATE_HUNGUP 	8

/*! Number of goertzels for progress detect */
enum gsamp_size {
	GSAMP_SIZE_NA = 183,			/*!< North America - 350, 440, 480, 620, 950, 1400, 1800 Hz */
	GSAMP_SIZE_CR = 188,			/*!< Costa Rica, Brazil - Only care about 425 Hz */
	GSAMP_SIZE_UK = 160			/*!< UK disconnect goertzel feed - should trigger 400hz */
};

enum prog_mode {
	PROG_MODE_NA = 0,
	PROG_MODE_CR,
	PROG_MODE_UK
};

enum freq_index {
	/*! For US modes { */
	HZ_350 = 0,
	HZ_400,
	HZ_425,
	HZ_440,
	HZ_450,
	HZ_480,
	HZ_620,
	HZ_950,
	HZ_1400,
	HZ_1800, /*!< } */
#if 0
	/*! For CR/BR modes */
	HZ_425 = 0,

	/*! For UK mode */
	HZ_350UK = 0,
	HZ_400UK,
	HZ_440UK
#endif 
};

/*!\brief This value is the minimum threshold, calculated by averaging all
 * of the samples within a frame, for which a frame is determined to either
 * be silence (below the threshold) or noise (above the threshold).  Please
 * note that while the default threshold is an even exponent of 2, there is
 * no requirement that it be so.  The threshold will accept any value between
 * 0 and 32767.
 */

enum busy_detect {
	BUSY_PERCENT = 10,	/*!< The percentage difference between the two last silence periods */
	BUSY_PAT_PERCENT = 7,	/*!< The percentage difference between measured and actual pattern */
	BUSY_THRESHOLD = 100,	/*!< Max number of ms difference between max and min times in busy */
	BUSY_MIN = 75,		/*!< Busy must be at least 80 ms in half-cadence */
	BUSY_MAX = 3100		/*!< Busy can't be longer than 3100 ms in half-cadence */
};

/*! Remember last 15 units */
#define DSP_HISTORY		15

#define TONE_THRESH		10.0	/*!< How much louder the tone should be than channel energy */
#define TONE_MIN_THRESH		1e8	/*!< How much tone there should be at least to attempt */

/*! All THRESH_XXX values are in GSAMP_SIZE chunks (us = 22ms) */
enum gsamp_thresh {
	THRESH_RING = 8,		/*!< Need at least 150ms ring to accept */
	THRESH_TALK = 2,		/*!< Talk detection does not work continuously */
	THRESH_BUSY = 4,		/*!< Need at least 80ms to accept */
	THRESH_CONGESTION = 4,		/*!< Need at least 80ms to accept */
	THRESH_HANGUP = 60,		/*!< Need at least 1300ms to accept hangup */
	THRESH_RING2ANSWER = 300	/*!< Timeout from start of ring to answer (about 6600 ms) */
};

#define	MAX_DTMF_DIGITS		128

/* Basic DTMF (AT&T) specs:
 *
 * Minimum tone on = 40ms
 * Minimum tone off = 50ms
 * Maximum digit rate = 10 per second
 * Normal twist <= 8dB accepted
 * Reverse twist <= 4dB accepted
 * S/N >= 15dB will detect OK
 * Attenuation <= 26dB will detect OK
 * Frequency tolerance +- 1.5% will detect, +-3.5% will reject
 */

#define DTMF_THRESHOLD		8.0e7
#define FAX_THRESHOLD		8.0e7
#define FAX_2ND_HARMONIC	2.0     /* 4dB */

#define DEF_DTMF_NORMAL_TWIST		6.31	 /* 8.0dB */
#define DEF_RELAX_DTMF_NORMAL_TWIST	6.31	 /* 8.0dB */

#ifdef	RADIO_RELAX
#define DEF_DTMF_REVERSE_TWIST		2.51	 /* 4.01dB */
#define DEF_RELAX_DTMF_REVERSE_TWIST	6.61	 /* 8.2dB */
#else
#define DEF_DTMF_REVERSE_TWIST		2.51	 /* 4.01dB */
#define DEF_RELAX_DTMF_REVERSE_TWIST	3.98	 /* 6.0dB */
#endif

#define DTMF_RELATIVE_PEAK_ROW	6.3     /* 8dB */
#define DTMF_RELATIVE_PEAK_COL	6.3     /* 8dB */
#define DTMF_2ND_HARMONIC_ROW       (relax ? 1.7 : 2.5)     /* 4dB normal */
#define DTMF_2ND_HARMONIC_COL	63.1    /* 18dB */
#define DTMF_TO_TOTAL_ENERGY	42.0

#define BELL_MF_THRESHOLD	1.6e9
#define BELL_MF_TWIST		4.0     /* 6dB */
#define BELL_MF_RELATIVE_PEAK	12.6    /* 11dB */

#if defined(BUSYDETECT_TONEONLY) && defined(BUSYDETECT_COMPARE_TONE_AND_SILENCE)
#error You cant use BUSYDETECT_TONEONLY together with BUSYDETECT_COMPARE_TONE_AND_SILENCE
#endif

/* The CNG signal consists of the transmission of 1100 Hz for 1/2 second,
 * followed by a 3 second silent (2100 Hz OFF) period.
 */
#define FAX_TONE_CNG_FREQ	1100
#define FAX_TONE_CNG_DURATION	500
#define FAX_TONE_CNG_DB		16

/* This signal may be sent by the Terminating FAX machine anywhere between
 * 1.8 to 2.5 seconds AFTER answering the call.  The CED signal consists
 * of a 2100 Hz tone that is from 2.6 to 4 seconds in duration.
*/
#define FAX_TONE_CED_FREQ	2100
#define FAX_TONE_CED_DURATION	2600
#define FAX_TONE_CED_DB		16

#define DEFAULT_SAMPLE_RATE		8000

/* MF goertzel size */
#define MF_GSIZE		120

/* DTMF goertzel size */
#define DTMF_GSIZE		102

/* How many successive hits needed to consider begin of a digit
 * IE. Override with dtmf_hits_to_begin=4 in dsp.conf
 */
#define DEF_DTMF_HITS_TO_BEGIN	2

/* How many successive misses needed to consider end of a digit
 * IE. Override with dtmf_misses_to_end=4 in dsp.conf
 */
#define DEF_DTMF_MISSES_TO_END	3

typedef struct {
	int v2;
	int v3;
	int chunky;
	int fac;
} goertzel_state_t;

typedef struct {
	int value;
	int power;
} goertzel_result_t;

typedef struct
{
	int freq;
	int block_size;
	int squelch;		/* Remove (squelch) tone */
	goertzel_state_t tone;
	float energy;		/* Accumulated energy of the current block */
	int samples_pending;	/* Samples remain to complete the current block */
	int mute_samples;	/* How many additional samples needs to be muted to suppress already detected tone */

	int hits_required;	/* How many successive blocks with tone we are looking for */
	float threshold;	/* Energy of the tone relative to energy from all other signals to consider a hit */

	int hit_count;		/* How many successive blocks we consider tone present */
	int nohit_count;
	int lhit;		/* Indicates if the last processed block was a hit */

} tone_detect_state_t;

typedef struct
{
	goertzel_state_t row_out[4];
	goertzel_state_t col_out[4];
	int hits;			/* How many successive hits we have seen already */
	int misses;			/* How many successive misses we have seen already */
	int lasthit;
	int current_hit;
	float energy;
	int current_sample;
	int mute_samples;
} dtmf_detect_state_t;

typedef struct
{
	goertzel_state_t tone_out[6];
	int current_hit;
	int hits[5];
	int current_sample;
	int mute_samples;
} mf_detect_state_t;

typedef struct
{
	char digits[MAX_DTMF_DIGITS + 1];
	int digitlen[MAX_DTMF_DIGITS + 1];
	int current_digits;
	int detected_digits;
	int lost_digits;

	union {
		dtmf_detect_state_t dtmf;
		mf_detect_state_t mf;
	} td;
} digit_detect_state_t;

struct dsp_busy_pattern {
	/*! Number of elements. */
	int length;
	/*! Pattern elements in on/off time durations. */
	int pattern[4];
};

typedef struct {
	int start;
	int end;
} fragment_t;

/* Note on tone suppression (squelching). Individual detectors (DTMF/MF/generic tone)
 * report fragments of the frame in which detected tone resides and which needs
 * to be "muted" in order to suppress the tone. To mark fragment for muting,
 * detectors call mute_fragment passing fragment_t there. Multiple fragments
 * can be marked and dsp_process later will mute all of them.
 *
 * Note: When tone starts in the middle of a Goertzel block, it won't be properly
 * detected in that block, only in the next. If we only mute the next block
 * where tone is actually detected, the user will still hear beginning
 * of the tone in preceeding block. This is why we usually want to mute some amount
 * of samples preceeding and following the block where tone was detected.
*/

struct dsp {
	//struct frame f;
	int threshold;
	int totalsilence;
	int totalnoise;
	int features;
	int ringtimeout;
	int busymaybe;
	int busycount;
	struct dsp_busy_pattern busy_cadence;
	int historicnoise[DSP_HISTORY];
	int historicsilence[DSP_HISTORY];
	goertzel_state_t freqs[10];
	int freqcount;
	int gsamps;
	enum gsamp_size gsamp_size;
	enum prog_mode progmode;
	int tstate;
	int tcount;
	int digitmode;
	int faxmode;
	int dtmf_began;
	int display_inband_dtmf_warning;
	float genergy;
	int mute_fragments;
	unsigned int sample_rate;
	fragment_t mute_data[5];
	digit_detect_state_t digit_state;
	tone_detect_state_t cng_tone_state;
	tone_detect_state_t ced_tone_state;
	unsigned int counter;
	bool last_zero;
	unsigned int loss;
	unsigned short int loss_hist[32];
	unsigned short int last_interval_loss_hist[32];
	unsigned int received;
};

enum threshold {
	/* Array offsets */
	THRESHOLD_SILENCE = 0,
	/* Always the last */
	THRESHOLD_MAX = 1,
};

enum dsp_process_res {
	DSP_PROCESS_RES_SILENCE        = 1 << 0,
	DSP_PROCESS_RES_BUSY           = 1 << 1,
	DSP_PROCESS_RES_DTMF           = 1 << 2,
	DSP_PROCESS_RES_FAX            = 1 << 3,
	DSP_PROCESS_RES_CALL_PROGRESSS = 1 << 4,
	DSP_PROCESS_RES_WAITDIALTONE   = 1 << 5,
};

/*! \brief Allocates a new dsp with a specific internal sample rate used
 * during processing. */
struct dsp *dsp_new_with_rate(unsigned int sample_rate);

/*! \brief Allocates a new dsp, assumes 8khz for internal sample rate */
struct dsp *dsp_new(void);

void dsp_free(struct dsp *dsp);

/*! \brief Retrieve the sample rate this DSP structure was
 * created with */
unsigned int dsp_get_sample_rate(const struct dsp *dsp);

/*! \brief Set threshold value for silence */
void dsp_set_threshold(struct dsp *dsp, int threshold);

/*! \brief Set number of required cadences for busy */
void dsp_set_busy_count(struct dsp *dsp, int cadences);

/*! \brief Set expected lengths of the busy tone */
void dsp_set_busy_pattern(struct dsp *dsp, const struct dsp_busy_pattern *cadence);

/*! \brief Scans for progress indication in audio */
int dsp_call_progress(struct dsp *dsp, struct frame *inf);

/*! \brief Set zone for doing progress detection */
int dsp_set_call_progress_zone(struct dsp *dsp, char *zone);

/*! \brief Return AST_FRAME_NULL frames when there is silence, AST_FRAME_BUSY on
   busies, and call progress, all dependent upon which features are enabled */
int dsp_process(struct dsp *dsp, short *data, int len, char *event_digit, int *event_len, int *silence, int *totalsilence, int *totalnoise, int *res_call_progress, u_int16_t *energylevel);

/*! \brief Return non-zero if this is silence.  Updates "totalsilence" with the total
   number of seconds of silence  */
int dsp_silence(struct dsp *dsp, short *data, int len, int *totalsilence);

/*! \brief Return non-zero if this is silence.  Updates "totalsilence" with the total
   number of seconds of silence. Returns the average energy of the samples in the frame
   in frames_energy variable. */
int dsp_silence_with_energy(struct dsp *dsp, short *data, int len, int *totalsilence, int *frames_energy);

/*!
 * \brief Return non-zero if this is noise.  Updates "totalnoise" with the total
 * number of seconds of noise
 * \since 1.6.1
 */
int dsp_noise(struct dsp *dsp, short *data, int len, int *totalnoise);

/*! \brief Return non-zero if historically this should be a busy, request that
  dsp_silence has already been called */
int dsp_busydetect(struct dsp *dsp);

/*! \brief Return non-zero if DTMF hit was found */
int dsp_digitdetect(struct dsp *dsp, struct frame *f);

/*! \brief Reset total silence count */
void dsp_reset(struct dsp *dsp);

/*! \brief Reset DTMF detector */
void dsp_digitreset(struct dsp *dsp);

/*! \brief Select feature set */
inline void dsp_set_features(struct dsp *dsp, int features)
{
	dsp->features = features;
	if (!(features & DSP_FEATURE_DIGIT_DETECT)) {
		dsp->display_inband_dtmf_warning = 0;
	}
}

/*! \brief Set feature */
inline void dsp_set_feature(struct dsp *dsp, int feature)
{
	dsp->features |= feature;
}

/*! \brief Clear feature */
inline void dsp_clear_feature(struct dsp *dsp, int feature)
{
	dsp->features &= ~feature;
}

/*! \brief Get pending DTMF/MF digits */
int dsp_getdigits(struct dsp *dsp, char *buf, int max);

/*! \brief Set digit mode
 * \version 1.6.1 renamed from dsp_digitmode to dsp_set_digitmode
 */
int dsp_set_digitmode(struct dsp *dsp, int digitmode);

/*! \brief Set fax mode */
int dsp_set_faxmode(struct dsp *dsp, int faxmode);

/*!
 * \brief Returns true if DSP code was muting any fragment of the last processed frame.
 * Muting (squelching) happens when DSP code removes DTMF/MF/generic tones from the audio
 * \since 1.6.1
 */
int dsp_was_muted(struct dsp *dsp);

/*! \brief Get tstate (Tone State) */
int dsp_get_tstate(struct dsp *dsp);

/*! \brief Get tcount (Threshold counter) */
int dsp_get_tcount(struct dsp *dsp);

/*!
 * \brief Get silence threshold from dsp.conf
 * \since 1.6.1
 */
int dsp_get_threshold_from_settings(enum threshold which);

/*!
 * \brief Reloads dsp settings from dsp.conf
 * \since 1.6.1
 */
int dsp_reload(void);

/*!
 * \brief Load dsp settings from dsp.conf
 * \since 1.6.1
 */
int dsp_init(void);

#endif /* _DSP_H */
