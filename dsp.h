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

struct dsp;

struct dsp_busy_pattern {
	/*! Number of elements. */
	int length;
	/*! Pattern elements in on/off time durations. */
	int pattern[4];
};

enum threshold {
	/* Array offsets */
	THRESHOLD_SILENCE = 0,
	/* Always the last */
	THRESHOLD_MAX = 1,
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
int dsp_process(struct dsp *dsp, short *data, int len, char *event_digit, int *event_len, int *silence, int *totalsilence, int *totalnoise);

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
void dsp_set_features(struct dsp *dsp, int features);

/*! \brief Set feature */
void dsp_set_feature(struct dsp *dsp, int feature);

/*! \brief Clear feature */
void dsp_clear_feature(struct dsp *dsp, int feature);

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
