#ifndef TRANSCRIBE_H
#define TRANSCRIBE_H


#include <string>
#include <list>
#include <deque>

#include "sync.h"


class Transcribe {
public:
	struct sCallChannel {
		sCallChannel() {
			index = 0;
			samplerate = 0;
			ok = false;
		}
		bool isFilled() {
			return(ok &&
			       !rslt_language.empty() &&
			       !rslt_text.empty() &&
			       !rslt_segments.empty());
		}
		unsigned index;
		string pcm;
		string pcm_16;
		string wav;
		unsigned samplerate;
		string country;
		string language;
		bool ok;
		string error;
		string rslt_language;
		string rslt_text;
		string rslt_segments;
	};
	struct sCall {
		sCall() {
			channels_count = 0;
		}
		bool isFilled() {
			for(unsigned i = 0; i < channels_count; i++) {
				if(channels[i].isFilled()) {
					return(true);
				}
			}
			return(false);
		}
		u_int64_t calltime_us;
		string callid;
		sCallChannel channels[2];
		unsigned channels_count;
	};
	struct sThread {
		sThread() {
			thread_handle = 0;
			thread_id = 0;
		}
		pthread_t thread_handle;
		int thread_id;
	};
	struct sSegment {
		u_int64_t start;
		u_int64_t stop;
		string text;
	};
	struct sRslt {
		string language;
		string text;
		string segments;
		string error;
		bool isOk() {
			return(!language.empty() &&
			       !text.empty() &&
			       !segments.empty());
		}
	};
	struct sTranscribeWavChannelParams {
		int16_t *data_wav;
		size_t data_wav_samples;
		int channels;
		int process_channel_i;
		string language;
		bool output_to_stdout;
		sRslt rslt;
		pthread_t thread;
		Transcribe *me;
		bool log;
	};
	enum _Whisper_ggml_log_level {
		_GGML_LOG_LEVEL_ERROR = 2,
		_GGML_LOG_LEVEL_WARN  = 3,
		_GGML_LOG_LEVEL_INFO  = 4,
		_GGML_LOG_LEVEL_DEBUG = 5
	};
	typedef void (*_Whisper_ggml_log_callback)(enum _Whisper_ggml_log_level level, const char * text, void * user_data);
	typedef void (*_Whisper_log_set)(_Whisper_ggml_log_callback log_callback, void * user_data);
	typedef void (*_Whisper_print_timings)(struct whisper_context * ctx);
	typedef int (*_Whisper_lang_id)(const char * lang);
	typedef const char * (*_Whisper_lang_str)(int id);
	typedef int (*_Whisper_full_lang_id)(struct whisper_context * ctx);
	typedef int (*_Whisper_full_n_segments)(struct whisper_context * ctx);
	typedef int64_t (*_Whisper_full_get_segment_t0)(struct whisper_context * ctx, int i_segment);
	typedef int64_t (*_Whisper_full_get_segment_t1)(struct whisper_context * ctx, int i_segment);
	typedef const char * (*_Whisper_full_get_segment_text)(struct whisper_context * ctx, int i_segment);
	typedef struct whisper_context * (*_Whisper_init_from_file)(const char * path_model);
	typedef int (*_Whisper_ctx_init_openvino_encoder)(struct whisper_context * ctx, const char * model_path, const char * device, const char * cache_dir);
	typedef int (*_Whisper_full_parallel_params_by_ref)(struct whisper_context * ctx, struct whisper_full_params * params, const float * samples, int n_samples, int n_processors, void * next_params);
	typedef void (*_Whisper_free)(struct whisper_context * ctx);
	struct sWhisperLib {
		sWhisperLib() {
			memset(this, 0, sizeof(*this));
		}
		bool init(const char *lib);
		void term();
		bool ok();
		void *lib_handle;
		_Whisper_log_set whisper_log_set;
		_Whisper_print_timings whisper_print_timings;
		_Whisper_lang_id whisper_lang_id;
		_Whisper_lang_str whisper_lang_str;
		_Whisper_full_lang_id whisper_full_lang_id;
		_Whisper_full_n_segments whisper_full_n_segments;
		_Whisper_full_get_segment_t0 whisper_full_get_segment_t0;
		_Whisper_full_get_segment_t1 whisper_full_get_segment_t1;
		_Whisper_full_get_segment_text whisper_full_get_segment_text;
		_Whisper_init_from_file whisper_init_from_file;
		_Whisper_ctx_init_openvino_encoder whisper_ctx_init_openvino_encoder;
		_Whisper_full_parallel_params_by_ref whisper_full_parallel_params_by_ref;
		_Whisper_free whisper_free;
	};
public:
	Transcribe();
	~Transcribe();
	bool transcribeWav(const char *wav, const char *json_params, bool output_to_stdout, map<unsigned, sRslt> *rslt, string *error);
	bool transcribeWavChannel(int16_t *data_wav, size_t data_wav_samples, int channels, int process_channel_i, string language, bool output_to_stdout, sRslt *rslt, sTranscribeWavChannelParams *params);
	bool transcribeWavChannel(sTranscribeWavChannelParams *params);
	static void *transcribeWavChannel_thread(void *params);
	void pushCall(sCall *call);
	static sCall *createTranscribeCall(class Call *call, const char *chanel1_pcm, const char *chanel2_pcm, unsigned samplerate);
	void processCall();
	static void *processThread(void *thread);
	void transcribeCall(sCall *call);
	unsigned getQueueSize() {
		lock_calls();
		size_t size = calls.size();
		unlock_calls();
		return(size);
	}
	unsigned getCountThreads() {
		lock_threads();
		size_t countThreads = threads.size();
		unlock_threads();
		return(countThreads);
	}
	void setTerminating() {
		threadsTerminating = 1;
	}
	bool runWhisperPython(int16_t *pcm_data, size_t pcm_data_samples, int pcm_data_samplerate,
			      string script, string python,
			      string model, string language, int timeout, bool deterministic, int threads,
			      string &rslt_language, string &rslt_text, string &rslt_segments,
			      string *error = NULL);
	bool runWhisperPython(string wav, string script, string python,
			      string model, string language, int timeout, bool deterministic, int threads,
			      string &rslt_language, string &rslt_text, string &rslt_segments,
			      string *error = NULL);
	string createWhisperPythonScript();
	bool runWhisperNative(const char *wav, const char *language, const char *model, int threads, 
			      string *language_detect, list<sSegment> *segments, string *error, 
			      bool log, sTranscribeWavChannelParams *params);
	bool runWhisperNative(float *pcm_data, size_t pcm_data_samples, const char *language, const char *model, int threads, 
			      string *language_detect, list<sSegment> *segments, string *error, 
			      bool log, sTranscribeWavChannelParams *params);
	void convertSegmentsToText(list<sSegment> *segments, string *text, string *segments_json);
	static string countryToLanguage(const char *country);
	static bool initNativeLib();
	static void termNativeLib();
	void saveProgress(sTranscribeWavChannelParams *params, int64_t t0, int64_t t1, const char *text);
private:
	void saveCallToDb(sCall *call);
	void destroyCall(sCall *call);
	void lock_calls() {
		__SYNC_LOCK_USLEEP(calls_sync, 20);
	}
	void unlock_calls() {
		__SYNC_UNLOCK(calls_sync);
	}
	void lock_threads() {
		__SYNC_LOCK_USLEEP(threads_sync, 20);
	}
	void unlock_threads() {
		__SYNC_UNLOCK(threads_sync);
	}
	void lock_progress_file() {
		__SYNC_LOCK_USLEEP(progress_file_sync, 20);
	}
	void unlock_progress_file() {
		__SYNC_UNLOCK(progress_file_sync);
	}
private:
	deque<sCall*> calls;
	volatile int calls_sync;
	list<sThread*> threads;
	volatile int threads_sync;
	unsigned int callsMax;
	unsigned int threadsMax;
	int threadsTerminating;
	volatile int progress_file_sync;
	static sWhisperLib nativeLib;
};


void transcribePushCall(Transcribe::sCall *call);
void transcribeCall(Transcribe::sCall *call);
string transcribeQueueLog();
void createTranscribe();
void destroyTranscribe();


#endif //TRANSCRIBE_H
