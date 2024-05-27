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
public:
	Transcribe();
	~Transcribe();
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
	bool runWhisper(string wav, string script, string python,
			string model, string language, int timeout, bool deterministic, int threads,
			string &rslt_language, string &rslt_text, string &rslt_segments,
			string *error = NULL);
	string createWhisperScript();
	static string countryToLanguage(const char *country);
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
private:
	deque<sCall*> calls;
	volatile int calls_sync;
	list<sThread*> threads;
	volatile int threads_sync;
	unsigned int callsMax;
	unsigned int threadsMax;
	int threadsTerminating;
};


void transcribePushCall(Transcribe::sCall *call);
void transcribeCall(Transcribe::sCall *call);
string transcribeQueueLog();
void createTranscribe();
void destroyTranscribe();


#endif //TRANSCRIBE_H
