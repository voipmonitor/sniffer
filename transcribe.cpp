#include <sys/resource.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <signal.h>
#include <curl/curl.h>

#include "config.h"

#if HAVE_LIBWHISPER
#include <whisper.h>
#endif

#include "calltable.h"
#include "audio_convert.h"
#include "tools.h"
#include "country_detect.h"
#include "common.h"

#include "transcribe.h"


extern int opt_audio_transcribe_threads;
extern int opt_audio_transcribe_queue_length_max;
extern bool opt_audio_transcribe_parallel_channel_processing;
extern bool opt_whisper_native;
extern string opt_whisper_model;
extern string opt_whisper_language;
extern int opt_whisper_timeout;
extern bool opt_whisper_deterministic_mode;
extern string opt_whisper_python;
extern int opt_whisper_threads;
extern string opt_whisper_native_lib;
extern string opt_audio_transcribe_progress_file;
extern string opt_audio_transcribe_control_file;
extern string opt_whisper_rest_api_url;

extern sVerbose sverb;

static Transcribe *transcribe;
static SqlDb *sqlDbSave;
static unsigned int transcribe_pid;

static const char* country_language_map[][2] = {
 { "AF", "ps" }, { "AL", "sq" }, { "DZ", "ar" }, { "AS", "en" }, { "AD", "ca" }, { "AO", "pt" }, { "AI", "en" }, { "AG", "en" }, { "AR", "es" }, { "AM", "hy" }, 
 { "AW", "nl" }, { "AU", "en" }, { "AT", "de" }, { "AZ", "az" }, { "BS", "en" }, { "BH", "ar" }, { "BD", "bn" }, { "BB", "en" }, { "BY", "be" }, { "BE", "nl" }, 
 { "BZ", "en" }, { "BJ", "fr" }, { "BM", "en" }, { "BT", "dz" }, { "BO", "es" }, { "BA", "bs" }, { "BW", "en" }, { "BR", "pt" }, { "BN", "ms" }, { "BG", "bg" }, 
 { "BF", "fr" }, { "BI", "fr" }, { "KH", "km" }, { "CM", "fr" }, { "CA", "en" }, { "CV", "pt" }, { "KY", "en" }, { "CF", "fr" }, { "TD", "fr" }, { "CL", "es" }, 
 { "CN", "zh" }, { "CO", "es" }, { "KM", "ar" }, { "CG", "fr" }, { "CR", "es" }, { "HR", "hr" }, { "CU", "es" }, { "CY", "el" }, { "CZ", "cs" }, { "DK", "da" }, 
 { "DJ", "fr" }, { "DM", "en" }, { "DO", "es" }, { "EC", "es" }, { "EG", "ar" }, { "SV", "es" }, { "GQ", "es" }, { "ER", "ti" }, { "EE", "et" }, { "ET", "am" }, 
 { "FJ", "en" }, { "FI", "fi" }, { "FR", "fr" }, { "GA", "fr" }, { "GM", "en" }, { "GE", "ka" }, { "DE", "de" }, { "GH", "en" }, { "GR", "el" }, { "GD", "en" }, 
 { "GT", "es" }, { "GN", "fr" }, { "GW", "pt" }, { "GY", "en" }, { "HT", "fr" }, { "HN", "es" }, { "HU", "hu" }, { "IS", "is" }, { "IN", "hi" }, { "ID", "id" }, 
 { "IR", "fa" }, { "IQ", "ar" }, { "IE", "en" }, { "IL", "he" }, { "IT", "it" }, { "JM", "en" }, { "JP", "ja" }, { "JO", "ar" }, { "KZ", "kk" }, { "KE", "sw" }, 
 { "KI", "en" }, { "KP", "ko" }, { "KR", "ko" }, { "KW", "ar" }, { "KG", "ky" }, { "LA", "lo" }, { "LV", "lv" }, { "LB", "ar" }, { "LS", "en" }, { "LR", "en" }, 
 { "LY", "ar" }, { "LI", "de" }, { "LT", "lt" }, { "LU", "lb" }, { "MG", "mg" }, { "MW", "en" }, { "MY", "ms" }, { "MV", "dv" }, { "ML", "fr" }, { "MT", "mt" }, 
 { "MH", "en" }, { "MR", "ar" }, { "MU", "en" }, { "MX", "es" }, { "FM", "en" }, { "MD", "ro" }, { "MC", "fr" }, { "MN", "mn" }, { "ME", "sr" }, { "MA", "ar" }, 
 { "MZ", "pt" }, { "MM", "my" }, { "NA", "en" }, { "NR", "en" }, { "NP", "ne" }, { "NL", "nl" }, { "NZ", "en" }, { "NI", "es" }, { "NE", "fr" }, { "NG", "en" }, 
 { "NO", "no" }, { "OM", "ar" }, { "PK", "ur" }, { "PW", "en" }, { "PA", "es" }, { "PG", "en" }, { "PY", "es" }, { "PE", "es" }, { "PH", "tl" }, { "PL", "pl" }, 
 { "PT", "pt" }, { "QA", "ar" }, { "RO", "ro" }, { "RU", "ru" }, { "RW", "rw" }, { "KN", "en" }, { "LC", "en" }, { "VC", "en" }, { "WS", "sm" }, { "SM", "it" }, 
 { "ST", "pt" }, { "SA", "ar" }, { "SN", "fr" }, { "RS", "sr" }, { "SC", "en" }, { "SL", "en" }, { "SG", "en" }, { "SK", "sk" }, { "SI", "sl" }, { "SB", "en" }, 
 { "SO", "so" }, { "ZA", "af" }, { "ES", "es" }, { "LK", "si" }, { "SD", "ar" }, { "SR", "nl" }, { "SZ", "en" }, { "SE", "sv" }, { "CH", "de" }, { "SY", "ar" }, 
 { "TW", "zh" }, { "TJ", "tg" }, { "TZ", "sw" }, { "TH", "th" }, { "TL", "pt" }, { "TG", "fr" }, { "TO", "en" }, { "TT", "en" }, { "TN", "ar" }, { "TR", "tr" }, 
 { "TM", "tk" }, { "UG", "en" }, { "UA", "uk" }, { "AE", "ar" }, { "GB", "en" }, { "US", "en" }, { "UY", "es" }, { "UZ", "uz" }, { "VU", "bi" }, { "VE", "es" }, 
 { "VN", "vi" }, { "YE", "ar" }, { "ZM", "en" }, { "ZW", "en" }
};


bool Transcribe::sWhisperLib::init(const char *lib) {
	lib_handle = dlopen(lib, RTLD_LAZY);
	if(!lib_handle) {
		return(false);
	}
	whisper_log_set = (_Whisper_log_set) dlsym(lib_handle, "whisper_log_set");
	whisper_print_timings = (_Whisper_print_timings) dlsym(lib_handle, "whisper_print_timings");
	whisper_lang_id = (_Whisper_lang_id) dlsym(lib_handle, "whisper_lang_id");
	whisper_lang_str = (_Whisper_lang_str) dlsym(lib_handle, "whisper_lang_str");
	whisper_full_lang_id = (_Whisper_full_lang_id) dlsym(lib_handle, "whisper_full_lang_id");
	whisper_full_n_segments = (_Whisper_full_n_segments) dlsym(lib_handle, "whisper_full_n_segments");
	whisper_full_get_segment_t0 = (_Whisper_full_get_segment_t0) dlsym(lib_handle, "whisper_full_get_segment_t0");
	whisper_full_get_segment_t1 = (_Whisper_full_get_segment_t1) dlsym(lib_handle, "whisper_full_get_segment_t1");
	whisper_full_get_segment_text = (_Whisper_full_get_segment_text) dlsym(lib_handle, "whisper_full_get_segment_text");
	whisper_init_from_file = (_Whisper_init_from_file) dlsym(lib_handle, "whisper_init_from_file");
	whisper_ctx_init_openvino_encoder = (_Whisper_ctx_init_openvino_encoder) dlsym(lib_handle, "whisper_ctx_init_openvino_encoder");
	whisper_full_parallel_params_by_ref = (_Whisper_full_parallel_params_by_ref) dlsym(lib_handle, "whisper_full_parallel_params_by_ref");
	whisper_free = (_Whisper_free) dlsym(lib_handle, "whisper_free");
	return(ok());
}

void Transcribe::sWhisperLib::term() {
	if(lib_handle) {
		dlclose(lib_handle);
		lib_handle = NULL;
	}
}

bool Transcribe::sWhisperLib::ok() {
	return(lib_handle != NULL &&
	       whisper_log_set != NULL &&
	       whisper_print_timings != NULL &&
	       whisper_lang_id != NULL &&
	       whisper_lang_str != NULL &&
	       whisper_full_lang_id != NULL &&
	       whisper_full_n_segments != NULL &&
	       whisper_full_get_segment_t0 != NULL &&
	       whisper_full_get_segment_t1 != NULL &&
	       whisper_full_get_segment_text != NULL &&
	       whisper_init_from_file != NULL &&
	       whisper_ctx_init_openvino_encoder != NULL &&
	       whisper_full_parallel_params_by_ref != NULL &&
	       whisper_free != NULL);
}

Transcribe::Transcribe() {
	callsMax = opt_audio_transcribe_queue_length_max;
	threadsMax = opt_audio_transcribe_threads;
	threadsTerminating = 0;
	calls_sync = 0;
	threads_sync= 0;
	progress_file_sync = 0;
}

Transcribe::~Transcribe() {
	setTerminating();
	while(true) {
		unsigned countThreads = getCountThreads();
		if(!countThreads) {
			break;
		}
		USLEEP(100000);
	}
}

bool Transcribe::transcribeWav(const char *wav, const char *json_params, bool output_to_stdout, map<unsigned, sRslt> *rslt, string *error) {
	setpriority(PRIO_PROCESS, get_unix_tid(), 20);
	JsonItem jsonParams;
	if(!opt_audio_transcribe_control_file.empty()) {
		transcribe_pid = getpid();
		pthread_t control_thread;
		vm_pthread_create("transcribe_control",
				  &control_thread, NULL, transcribeControlThread, NULL, __FILE__, __LINE__);
	}
	jsonParams.parse(json_params);
	string language_type_ch[2];
	string language_ch[2];
	string country_ch[2];
	for(unsigned i = 0; i < 2; i++) {
		language_type_ch[i] = jsonParams.getValue("ch_" + intToString(i + 1) + "_language_type");
		language_ch[i] = jsonParams.getValue("ch_" + intToString(i + 1) + "_language");
		country_ch[i] = jsonParams.getValue("ch_" + intToString(i + 1) + "_country");
		if(language_ch[i].empty() && !country_ch[i].empty()) {
			language_ch[i] = countryToLanguage(country_ch[i].c_str());
		}
	}
	cAudioConvert ac;
	ac.fileName = wav;
	cAudioConvert::sWavHeader wavHeader;
	if(!ac.readWavHeader(&wavHeader)) {
		string error_str = "failed load wav header";
		if(output_to_stdout) {
			cout << "ERROR: " << error_str;
		}
		if(error) {
			*error = error_str;
		}
		return(false);
	}
	int16_t *data_wav;
	size_t data_wav_samples;
	if(ac.loadWav((u_char**)&data_wav, &data_wav_samples) != cAudioConvert::_rslt_ok) {
		string error_str = "failed load wav";
		if(output_to_stdout) {
			cout << "ERROR: " << error_str;
		}
		if(error) {
			*error = error_str;
		}
		return(false);
	}
	int reserve_samples = 10;
	if(wavHeader.sampleRate != 16000) {
		double ratio = 16000. / wavHeader.sampleRate;
		size_t data_wav_16_samples = data_wav_samples * ratio;
		int16_t *data_wav_16 = new FILE_LINE(0) int16_t[data_wav_16_samples + reserve_samples];
		size_t pos_src = 0;
		while(pos_src < data_wav_samples) {
			size_t pos_dst = pos_src * ratio;
			size_t block_size = min((size_t)ac.resample_chunk_length, data_wav_samples - pos_src);
			ac.linear_resample(data_wav + pos_src, data_wav_16 + pos_dst, block_size, ratio, wavHeader.channels);
			pos_src += block_size;
		}
		delete [] data_wav;
		data_wav = data_wav_16;
		data_wav_samples = data_wav_16_samples;
	}
	bool rslt_rslt = false;
	string last_rslt_error;
	
	// Check if we're using stereo mode with REST API
	if(!opt_whisper_rest_api_url.empty() && opt_whisper_rest_api_mode == "stereo" && wavHeader.channels == 2) {
		// Process stereo file as single request
		sRslt stereoResults[2];
		string error;
		if(runWhisperRestApiStereo(wav, stereoResults, &error)) {
			if(rslt) {
				(*rslt)[0] = stereoResults[0];
				(*rslt)[1] = stereoResults[1];
			}
			rslt_rslt = stereoResults[0].isOk() || stereoResults[1].isOk();
			if(!stereoResults[0].isOk()) last_rslt_error = stereoResults[0].error;
			if(!stereoResults[1].isOk()) last_rslt_error = stereoResults[1].error;
		} else {
			if(rslt) {
				(*rslt)[0].error = error;
				(*rslt)[1].error = error;
			}
			last_rslt_error = error;
		}
	} else {
		// Original split mode
		sTranscribeWavChannelParams transcribeChannelsParams[wavHeader.channels];
		for(unsigned chi = 0; chi < wavHeader.channels; chi++) {
			string language;
			if(!language_type_ch[chi].empty()) {
				language = language_type_ch[chi] == "auto" ? "" : 
					   language_type_ch[chi] == "by_number" ? language_ch[chi] :
					   language_type_ch[chi] == "set" ? language_ch[chi] :
					   opt_whisper_language;
			} else {
				language = opt_whisper_language == "auto" ? "" : 
					   opt_whisper_language == "by_number" ? language_ch[chi] : 
					   opt_whisper_language;
			}
			transcribeChannelsParams[chi].data_wav = data_wav;
			transcribeChannelsParams[chi].data_wav_samples = data_wav_samples;
			transcribeChannelsParams[chi].channels = wavHeader.channels;
			transcribeChannelsParams[chi].process_channel_i = chi;
			transcribeChannelsParams[chi].language = language;
			transcribeChannelsParams[chi].output_to_stdout = output_to_stdout;
			transcribeChannelsParams[chi].thread = 0;
			transcribeChannelsParams[chi].me = this;
		}
		if(wavHeader.channels > 1 && opt_audio_transcribe_parallel_channel_processing) {
			for(unsigned chi = 0; chi < wavHeader.channels; chi++) {
				vm_pthread_create("transcribe",
						  &transcribeChannelsParams[chi].thread, NULL, transcribeWavChannel_thread, &transcribeChannelsParams[chi], __FILE__, __LINE__);
			}
			for(unsigned chi = 0; chi < wavHeader.channels; chi++) {
				pthread_join(transcribeChannelsParams[chi].thread, NULL);
			}
		} else {
			for(unsigned chi = 0; chi < wavHeader.channels; chi++) {
				transcribeWavChannel(&transcribeChannelsParams[chi]);
			}
		}
		// Process results from split mode
		for(unsigned chi = 0; chi < wavHeader.channels; chi++) {
			if(transcribeChannelsParams[chi].rslt.isOk()) {
				rslt_rslt = true;
			} else {
				last_rslt_error = transcribeChannelsParams[chi].rslt.error;
			}
			if(rslt) {
				(*rslt)[chi] = transcribeChannelsParams[chi].rslt;
			}
		}
	}
	if(!rslt_rslt) {
		if(output_to_stdout) {
			cout << "ERROR: " << find_and_replace_all(last_rslt_error, "\n", "\\n");
		}
		if(error) {
			*error = last_rslt_error;
		}
	}
	delete [] data_wav;
	return(rslt_rslt);
}

bool Transcribe::transcribeWavChannel(int16_t *data_wav, size_t data_wav_samples, int channels, int process_channel_i, string language, bool output_to_stdout, sRslt *rslt, sTranscribeWavChannelParams *params) {
	int reserve_samples = 10;
	size_t data_wav_channel_samples = data_wav_samples / channels;
	int16_t *data_wav_channel = opt_whisper_native ?
				     (int16_t*)(new FILE_LINE(0) float[data_wav_channel_samples + reserve_samples]) :
				     new FILE_LINE(0) int16_t[data_wav_channel_samples + reserve_samples];
	for(size_t i = 0; i < data_wav_channel_samples; i++) {
		int16_t sample = data_wav[i * channels + process_channel_i];
		if(opt_whisper_native) {
			((float*)data_wav_channel)[i] = sample / 32768.0;
		} else {
			data_wav_channel[i] = sample;
		}
	}
	bool rslt_ok = false;
	bool rslt_whisper;
	string rslt_language;
	string rslt_text;
	string rslt_segments;
	string rslt_error;
	if(opt_whisper_native) {
		list<sSegment> segments;
		rslt_whisper = runWhisperNative((float*)data_wav_channel, data_wav_channel_samples,
						language.empty() ? "auto" : language.c_str(), opt_whisper_model.c_str(), opt_whisper_threads, 
						&rslt_language, &segments, &rslt_error, sverb.whisper, params);
		if(rslt_whisper && segments.size()) {
			convertSegmentsToText(&segments, &rslt_text, &rslt_segments);
		}
	} else {
		rslt_whisper = runWhisperPython(data_wav_channel, data_wav_channel_samples, 16000,
						"", opt_whisper_python,
						opt_whisper_model, language, opt_whisper_timeout, opt_whisper_deterministic_mode, opt_whisper_threads,
						rslt_language, rslt_text, rslt_segments,
						&rslt_error);
	}
	if(rslt_whisper  &&
	   !rslt_language.empty() && !rslt_text.empty() && !rslt_segments.empty()) {
		if(output_to_stdout) {
			cout << "CH_" << (process_channel_i + 1) << "_LANG: " << rslt_language << endl
			     << "CH_" << (process_channel_i + 1) << "_TEXT: " << find_and_replace_all(rslt_text, "\n", "\\n") << endl
			     << "CH_" << (process_channel_i + 1) << "_SEGM: " << find_and_replace_all(rslt_segments, "\n", "\\n") << endl;
		}
		if(rslt) {
			rslt->language = rslt_language;
			rslt->text = rslt_text;
			rslt->segments = rslt_segments;
		}
		rslt_ok = true;
	} else {
		if(rslt_error.empty()) {
			rslt_error = "unknown error in call whisper";
		}
		if(output_to_stdout) {
			cout << "CH_" << (process_channel_i + 1) << "_ERROR: " << find_and_replace_all(rslt_error, "\n", "\\n")  << endl;
		}
		if(rslt) {
			rslt->error = rslt_error;
		}
	}
	delete [] data_wav_channel;
	return(rslt_ok);
}

bool Transcribe::transcribeWavChannel(sTranscribeWavChannelParams *params) {
	return(transcribeWavChannel(params->data_wav, 
				    params->data_wav_samples, 
				    params->channels, 
				    params->process_channel_i, 
				    params->language, 
				    params->output_to_stdout, 
				    &params->rslt,
				    params));
}

void *Transcribe::transcribeWavChannel_thread(void *params) {
	sTranscribeWavChannelParams *tr_params = (sTranscribeWavChannelParams*)params;
	tr_params->me->transcribeWavChannel(tr_params);
	return(NULL);
}

void Transcribe::pushCall(sCall *call) {
	if(getQueueSize() < callsMax) {
		lock_calls();
		calls.push_back(call);
		unlock_calls();
		processCall();
	} else {
		destroyCall(call);
	}
}

Transcribe::sCall *Transcribe::createTranscribeCall(Call *call, const char *chanel1_pcm, const char *chanel2_pcm, unsigned samplerate, const char *stereo_wav) {
	sCall *call_tr = new FILE_LINE(0) sCall;
	call_tr->calltime_us = call->calltime_us();
	call_tr->callid = call->fbasename;
	CallBranch *c_branch = call->branch_main();
	if(chanel1_pcm) {
		call_tr->channels[call_tr->channels_count].index = 1;
		call_tr->channels[call_tr->channels_count].pcm = chanel1_pcm;
		call_tr->channels[call_tr->channels_count].samplerate = samplerate;
		call_tr->channels[call_tr->channels_count].country = getCountryByPhoneNumber(c_branch->caller.c_str(), call->getSipcallerip(c_branch), true);
		call_tr->channels[call_tr->channels_count].language = countryToLanguage(call_tr->channels[call_tr->channels_count].country.c_str());
		++call_tr->channels_count;
	}
	if(chanel2_pcm) {
		call_tr->channels[call_tr->channels_count].index = 2;
		call_tr->channels[call_tr->channels_count].pcm = chanel2_pcm;
		call_tr->channels[call_tr->channels_count].samplerate = samplerate;
		call_tr->channels[call_tr->channels_count].country = getCountryByPhoneNumber(call->get_called(c_branch), c_branch->sipcalledip_rslt, true);
		call_tr->channels[call_tr->channels_count].language = countryToLanguage(call_tr->channels[call_tr->channels_count].country.c_str());
		++call_tr->channels_count;
	}
	if(stereo_wav) {
		call_tr->stereo_wav = stereo_wav;
	}
	return(call_tr);
}

void Transcribe::processCall() {
	lock_calls();
	if(calls.size() && 
	   calls.size() > threads.size() * 2 && 
	   threads.size() < threadsMax) {
		lock_threads();
		sThread *new_hread = new FILE_LINE(0) sThread();
		threads.push_back(new_hread);
		vm_pthread_create_autodestroy("audio convert",
					      &new_hread->thread_handle, NULL, this->processThread, new_hread, __FILE__, __LINE__);
		unlock_threads();
	}
	unlock_calls();
}

void *Transcribe::processThread(void *thread) {
	((sThread*)thread)->thread_id = get_unix_tid();
	//setpriority(PRIO_PROCESS, ((sThread*)thread)->thread_id, 20);
	u_long last_use_at = getTimeS();
	while(!transcribe->threadsTerminating) {
		transcribe->lock_calls();
		sCall *call = NULL;
		if(transcribe->calls.size()) {
			call = transcribe->calls.front();
			transcribe->calls.pop_front();
		}
		transcribe->unlock_calls();
		if(call) {
			transcribe->transcribeCall(call);
			last_use_at = getTimeS();
		} else {
			if((getTimeS() - last_use_at) > 5 * 60) {
				break;
			} else {
				USLEEP(1000);
			}
		}
	}
	transcribe->lock_threads();
	transcribe->threads.remove((sThread*)thread);
	transcribe->unlock_threads();
	delete (sThread*)thread;
	return(NULL);
}

void Transcribe::transcribeCall(sCall *call) {
	for(unsigned i = 0; i < call->channels_count; i++) {
		call->channels[i].ok = true;
		if(call->channels[i].samplerate != 16000) {
			call->channels[i].pcm_16 = call->channels[i].pcm + ".16";
			cAudioConvert ac;
			ac.fileName = call->channels[i].pcm;
			cAudioConvert::sAudioInfo ai;
			ai.sampleRate = call->channels[i].samplerate;
			ai.channels = 1;
			ai.bitsPerSample = 16;
			cAudioConvert::eResult rslt = ac.resampleRaw(&ai, call->channels[i].pcm_16.c_str(), 16000);
			if(rslt != cAudioConvert::_rslt_ok) {
				call->channels[i].ok = false;
				call->channels[i].error = "failed resample to 16kHz - " + cAudioConvert::getRsltStr(rslt);
				continue;
			}
		}
		call->channels[i].wav = call->channels[i].pcm + ".WAV";
		cAudioConvert src;
		src.fileName = call->channels[i].pcm_16.empty() ? call->channels[i].pcm : call->channels[i].pcm_16;
		cAudioConvert dst;
		dst.formatType = cAudioConvert::_format_wav;
		dst.srcDstType = cAudioConvert::_dst;
		dst.fileName = call->channels[i].wav;
		src.destAudio = &dst;
		cAudioConvert::sAudioInfo ai;
		ai.sampleRate = 16000;
		ai.channels = 1;
		ai.bitsPerSample = 16;
		cAudioConvert::eResult rslt = src.readRaw(&ai);
		if(rslt != cAudioConvert::_rslt_ok) {
			call->channels[i].ok = false;
			call->channels[i].error = "failed convert to wav - " + cAudioConvert::getRsltStr(rslt);
			continue;
		}
	}
	// Check if we should use stereo mode
	if(!opt_whisper_rest_api_url.empty() && opt_whisper_rest_api_mode == "stereo" && call->channels_count == 2 && 
	   call->channels[0].ok && call->channels[1].ok) {
		string stereoWav;
		bool createdTempFile = false;
		
		if(!call->stereo_wav.empty()) {
			// Use existing stereo WAV file
			stereoWav = call->stereo_wav;
		} else {
			// Create stereo WAV from mono files
			// Use base name without channel suffix for stereo file
			string basePath = call->channels[0].pcm;
			size_t pos = basePath.rfind(".i0");
			if(pos != string::npos) {
				basePath = basePath.substr(0, pos);
			}
			stereoWav = basePath + "_stereo.WAV";
			createdTempFile = true;
			
			bool mergeSuccess = ac_file_mix((char*)call->channels[0].wav.c_str(), 
			                                (char*)call->channels[1].wav.c_str(), 
			                                (char*)stereoWav.c_str(), 
			                                cAudioConvert::_format_wav, 
			                                16000, // sampleRate
			                                true,  // stereo
			                                false, // swap
			                                0.4,   // quality
			                                false); // destInSpool
			if(!mergeSuccess) {
				call->channels[0].ok = false;
				call->channels[0].error = "failed to merge WAV files for stereo mode";
				call->channels[1].ok = false;
				call->channels[1].error = "failed to merge WAV files for stereo mode";
			}
		}
		
		if(call->channels[0].ok && call->channels[1].ok) {
			string error;
			sRslt stereoResults[2];
			if(runWhisperRestApiStereo(stereoWav.c_str(), stereoResults, &error)) {
				// Apply results to channels
				call->channels[0].rslt_language = stereoResults[0].language;
				call->channels[0].rslt_text = stereoResults[0].text;
				call->channels[0].rslt_segments = stereoResults[0].segments;
				
				call->channels[1].rslt_language = stereoResults[1].language;
				call->channels[1].rslt_text = stereoResults[1].text;
				call->channels[1].rslt_segments = stereoResults[1].segments;
			} else {
				call->channels[0].ok = false;
				call->channels[0].error = !error.empty() ? error : "failed transcribe via whisper (rest_api stereo)";
				call->channels[1].ok = false;
				call->channels[1].error = !error.empty() ? error : "failed transcribe via whisper (rest_api stereo)";
			}
		}
		
		// Clean up temporary stereo file if we created it
		if(createdTempFile && !sverb.noaudiounlink) {
			if(sverb.whisper) {
				cout << "whisper rest api stereo - removing temporary file: " << stereoWav << endl;
			}
			unlink(stereoWav.c_str());
		}
	} else {
		// Original split mode processing
		for(unsigned i = 0; i < call->channels_count; i++) {
			if(call->channels[i].ok) {
				string rslt_language;
				string rslt_text;
				string rslt_segments;
				string language = opt_whisper_language == "auto" ? "" : 
						  opt_whisper_language == "by_number" ? call->channels[i].language : opt_whisper_language;
				string error;
				if(!opt_whisper_rest_api_url.empty()) {
					if(runWhisperRestApi(call->channels[i].wav.c_str(), rslt_language, rslt_text, rslt_segments, &error)) {
						call->channels[i].rslt_language = rslt_language;
						call->channels[i].rslt_text = rslt_text;
						call->channels[i].rslt_segments = rslt_segments;
					} else {
						call->channels[i].ok = false;
						call->channels[i].error = !error.empty() ? error : "failed transcribe via whisper (rest_api)";
					}
				} else if(opt_whisper_native) {
					list<sSegment> segments;
					if(runWhisperNative(call->channels[i].wav.c_str(), language.empty() ? "auto" : language.c_str(), opt_whisper_model.c_str(), opt_whisper_threads, 
							    &rslt_language, &segments, &error, sverb.whisper, NULL) && segments.size()) {
						call->channels[i].rslt_language = rslt_language;
						convertSegmentsToText(&segments, &call->channels[i].rslt_text, &call->channels[i].rslt_segments);
					} else {
						call->channels[i].ok = false;
						call->channels[i].error = !error.empty() ? error : "failed transcribe via whisper (native)";
					}
				} else {
					if(runWhisperPython(call->channels[i].wav, "", opt_whisper_python,
							    opt_whisper_model, language, opt_whisper_timeout, opt_whisper_deterministic_mode, opt_whisper_threads,
							    rslt_language, rslt_text, rslt_segments,
							    &error) &&
					   !rslt_language.empty() &&
					   !rslt_text.empty() &&
					   !rslt_segments.empty()) {
						call->channels[i].rslt_language = rslt_language;
						call->channels[i].rslt_text = rslt_text;
						call->channels[i].rslt_segments = rslt_segments;
					} else {
						call->channels[i].ok = false;
						call->channels[i].error = !error.empty() ? error : "failed transcribe via whisper (python)";
					}
				}
			}
			if(!call->channels[i].ok) {
				syslog(LOG_ERR, "transcribe call [%s]: %s", call->callid.c_str(), call->channels[i].error.c_str());
			}
		}
	}
	saveCallToDb(call);
	destroyCall(call);
}

bool Transcribe::runWhisperPython(int16_t *pcm_data, size_t pcm_data_samples, int pcm_data_samplerate,
				  string script, string python,
				  string model, string language, int timeout, bool deterministic, int threads,
				  string &rslt_language, string &rslt_text, string &rslt_segments,
				  string *error) {
	string wav_file = tmpnam();
	if(wav_file.empty()) {
		if(error) {
			*error = "failed create wav file";
		}
		return("");
	}
	wav_file = wav_file + ".wav";
	cAudioConvert ac;
	ac.fileName = wav_file;
	ac.audioInfo.sampleRate = pcm_data_samplerate;
	ac.audioInfo.channels = 1;
	ac.audioInfo.bitsPerSample = 16;
	ac.srcDstType = cAudioConvert::_dst;
	if(!ac.open_for_write()) {
		if(error) {
			*error = "failed create template wav";
		}
		return(false);
	}
	if(ac.writeWavHeader() != cAudioConvert::_rslt_ok) {
		if(error) {
			*error = "failed write header to template wav";
		}
		return(false);
	}
	if(ac.writeWavData((u_char*)pcm_data, pcm_data_samples * sizeof(int16_t) / sizeof(u_char)) != cAudioConvert::_rslt_ok) {
		if(error) {
			*error = "failed write header to template wav";
		}
		return(false);
	}
	if(ac.writeWavEnd() != cAudioConvert::_rslt_ok) {
		if(error) {
			*error = "failed write header to template wav";
		}
		return(false);
	}
	ac.close();
	//cout << ac.fileName << endl;
	bool rslt = runWhisperPython(wav_file, script, python,
				     model, language, timeout, deterministic, threads,
				     rslt_language, rslt_text, rslt_segments,
				     error);
	unlink(wav_file.c_str());
	return(rslt);
}

bool Transcribe::runWhisperPython(string wav, string script, string python,
				  string model, string language, int timeout, bool deterministic_mode, int threads,
				  string &rslt_language, string &rslt_text, string &rslt_segments,
				  string *error) {
	bool createdWhisperScript = false;
	if(script.empty()) {
		script = createWhisperPythonScript();
		if(script.empty()) {
			return(false);
		}
		createdWhisperScript = true;
	}
	string cmd = (!python.empty() ? python + " " + escapeShellArgument(script) : script) + " " + 
		     escapeShellArgument(wav) + " " +
		     (!model.empty() ? "--model " + escapeShellArgument(model) + " " : "") +
		     (!language.empty() ? "--language " + escapeShellArgument(language) + " " : "") +
		     (deterministic_mode ? "--deterministic " : "") + 
		     (threads > 0 ? "--threads " + intToString(threads) + " " : "");
	if(sverb.whisper) {
		cout << "whisper cmd: " << cmd << endl;
	}
	int exitCode;
	SimpleBuffer out;
	SimpleBuffer err;
	vm_pexec(cmd.c_str(), &out, &err, &exitCode, timeout);
	if(createdWhisperScript) {
		unlink(script.c_str());
	}
	if(sverb.whisper) {
		cout << "whisper exit code: " << exitCode << endl;
		if(out.size()) {
			cout << "whisper stdout: " << (char*)out << endl;
		}
		if(err.size()) {
			cout << "whisper stderr: " << (char*)err << endl;
		}
	}
	if(exitCode == 0 && out.size()) {
		vector<string> out_a = explode(out, '\n');
		for(unsigned i = 0; i < out_a.size(); i++) {
			if(out_a[i].substr(0, 6) == "LANG: ") {
				rslt_language = out_a[i].substr(6);
			} else if(out_a[i].substr(0, 6) == "TEXT: ") {
				rslt_text = out_a[i].substr(6);
			} else if(out_a[i].substr(0, 6) == "RSLT: ") {
				rslt_segments = out_a[i].substr(6);
			}
		}
		return(true);
	} else if(error) {
		ostringstream outStr;
		outStr << "whisper error " << exitCode;
		if(err.size()) {
			outStr << " - " << (char*)err;
		}
		*error = outStr.str();
	}
	return(false);
}

string Transcribe::createWhisperPythonScript() {
	string scriptName = tmpnam();
	if(scriptName.empty()) {
		return("");
	}
	scriptName = scriptName + ".py";
	FILE *fileHandle = fopen(scriptName.c_str(), "wt");
	if(!fileHandle) {
		return("");
	}
	string scriptContent = 
"#!/usr/bin/python3\n\
\n\
import whisper\n\
import torch\n\
import numpy as np\n\
import random\n\
import sys\n\
import argparse\n\
import os\n\
\n\
def set_seed(seed):\n\
    torch.manual_seed(seed)\n\
    torch.cuda.manual_seed(seed)\n\
    torch.cuda.manual_seed_all(seed)\n\
    np.random.seed(seed)\n\
    random.seed(seed)\n\
    torch.backends.cudnn.deterministic = True\n\
    torch.backends.cudnn.benchmark = False\n\
\n\
def transcribe(audio_path, language=None, model_name=\"large\", deterministic=False):\n\
    if deterministic:\n\
        set_seed(42)\n\
    model = whisper.load_model(model_name)\n\
    model.eval()\n\
    if language:\n\
        result = model.transcribe(audio_path, language=language)\n\
    else:\n\
        result = model.transcribe(audio_path)\n\
    return result['text'], result['segments'], result['language']\n\
\n\
if __name__ == \"__main__\":\n\
    parser = argparse.ArgumentParser(description=\"Transcribe audio using Whisper with optional deterministic behavior\")\n\
    parser.add_argument(\"audio_path\", type=str, help=\"Path to the audio file\")\n\
    parser.add_argument(\"--model\", type=str, default=\"small\", help=\"Whisper model to use (e.g., tiny, base, small, medium, large)\")\n\
    parser.add_argument(\"--language\", type=str, help=\"Language code (ISO 639-1) for the transcription\")\n\
    parser.add_argument(\"--deterministic\", action='store_true', help=\"Enable deterministic behavior\")\n\
    parser.add_argument(\"--threads\", type=int, help=\"Limit the number of threads used by PyTorch and other libraries\")\n\
\n\
    args = parser.parse_args()\n\
\n\
    if args.threads:\n\
        os.environ[\"OMP_NUM_THREADS\"] = str(args.threads)\n\
        os.environ[\"MKL_NUM_THREADS\"] = str(args.threads)\n\
        torch.set_num_threads(args.threads)\n\
        torch.set_num_interop_threads(args.threads)\n\
\n\
    text, segments, language = transcribe(args.audio_path, args.language, args.model, args.deterministic)\n\
    print(f\"LANG: {language}\")\n\
    print(f\"TEXT: {text}\")\n\
    print(f\"RSLT: {segments}\")\n\
";
	bool okWrite = fwrite(scriptContent.c_str(), 1, scriptContent.length(), fileHandle) == scriptContent.length();
	fclose(fileHandle);
	if(!okWrite ||
	   chmod(scriptName.c_str(), 0755)) {
		unlink(scriptName.c_str());
		return("");
	}
	return(scriptName);
}

#if HAVE_LIBWHISPER
static string to_timestamp(int64_t t, bool comma = false) {
	int64_t msec = t * 10;
	int64_t hr = msec / (1000 * 60 * 60);
	msec = msec - hr * (1000 * 60 * 60);
	int64_t min = msec / (1000 * 60);
	msec = msec - min * (1000 * 60);
	int64_t sec = msec / 1000;
	msec = msec - sec * 1000;
	char buf[32];
	snprintf(buf, sizeof(buf), "%02d:%02d:%02d%s%03d", (int) hr, (int) min, (int) sec, comma ? "," : ".", (int) msec);
	return string(buf);
}
static void whisper_native_print_segment_callback(struct whisper_context * ctx, struct whisper_state * /*state*/, int n_new, void * user_data) {
	Transcribe::sTranscribeWavChannelParams *params = (Transcribe::sTranscribeWavChannelParams*)user_data;
	const int n_segments = whisper_full_n_segments(ctx);
	const int s0 = n_segments - n_new;
	if(s0 == 0 && (!params || params->log)) {
		printf("\n");
	}
	for(int i = s0; i < n_segments; i++) {
		int64_t t0 = whisper_full_get_segment_t0(ctx, i);
		int64_t t1 = whisper_full_get_segment_t1(ctx, i);
		const char *text = whisper_full_get_segment_text(ctx, i);
		if(!params || params->log) {
			printf("[%s --> %s]  ", to_timestamp(t0).c_str(), to_timestamp(t1).c_str());
			printf("%s", text);
			printf("\n");
			fflush(stdout);
		}
		if(params && !opt_audio_transcribe_progress_file.empty()) {
			params->me->saveProgress(params, t0, t1, text);
		}
	}
}
#endif

#if HAVE_LIBWHISPER
static void whisper_native_cb_log_disable(enum ggml_log_level , const char * , void * ) {
}
#endif
static void _whisper_native_cb_log_disable(enum Transcribe::_Whisper_ggml_log_level , const char * , void * ) {
}

bool Transcribe::runWhisperNative(const char *wav, const char *language, const char *model, int threads, 
				  string *language_detect, list<sSegment> *segments, string *error, 
				  bool log, sTranscribeWavChannelParams *params) {
	float *pcm_data;
	size_t pcm_data_samples;
	cAudioConvert src;
	src.fileName = wav;
	if(src.loadWav((u_char**)&pcm_data, &pcm_data_samples, true) != cAudioConvert::_rslt_ok) {
		*error = "failed load wav";
		return(false);
	}
	bool rslt = runWhisperNative(pcm_data, pcm_data_samples, language, model, threads, 
				     language_detect, segments, error, 
				     log, params);
	delete [] pcm_data;
	return(rslt);
}

bool Transcribe::runWhisperNative(float *pcm_data, size_t pcm_data_samples, const char *language, const char *model, int threads, 
				  string *language_detect, list<sSegment> *segments, string *error, 
				  bool log, sTranscribeWavChannelParams *params) {
	if(opt_whisper_native_lib.empty()) {
		#if HAVE_LIBWHISPER
		if(strcasecmp(language, "auto") && whisper_lang_id(language) == -1) {
			*error = "unknown language";
			return(false);
		}
		#endif
	} else {
		if(strcasecmp(language, "auto") && nativeLib.whisper_lang_id(language) == -1) {
			*error = "unknown language";
			return(false);
		}
	}
	float max_sample = 0;
	for(size_t i = 0; i < pcm_data_samples; i++) {
		if(fabs(pcm_data[i]) > max_sample) {
			max_sample = fabs(pcm_data[i]);
		}
	}
	if(sverb.whisper) {
		cout << "max sample: " << max_sample << endl;
	}
	if(max_sample > 0.001) {
		if(opt_whisper_native_lib.empty()) {
			#if HAVE_LIBWHISPER
			#if defined(__x86_64__)
			if(!check_sse3() || !check_ssse3() || !check_avx() || !check_f16c() || !check_fma() || !check_avx2()) {
				ostringstream outStr;
				outStr << "too old cpu" << endl
				       << " - sse3: " << (check_sse3() ? "ok" : "missing") << endl
				       << " - ssse3: " << (check_ssse3() ? "ok" : "missing") << endl
				       << " - avx: " << (check_avx() ? "ok" : "missing") << endl
				       << " - f16c: " << (check_f16c() ? "ok" : "missing") << endl
				       << " - fma: " << (check_fma() ? "ok" : "missing") << endl
				       << " - avx2: " << (check_avx2() ? "ok" : "missing") << endl;
				*error = outStr.str();
				return(false);
			}
			#else
			*error = "whisper.cpp is only available on x86_64";
			return(false);
			#endif
			if(!log) {
				whisper_log_set(whisper_native_cb_log_disable, NULL);
			}
			struct whisper_context_params cparams = whisper_context_default_params();
			struct whisper_context *ctx = whisper_init_from_file_with_params(model, cparams);
			if(!ctx) {
				*error = "failed to initialize whisper context";
				return(false);
			}
			whisper_ctx_init_openvino_encoder(ctx, NULL, "cpu", NULL);
			whisper_full_params wparams = whisper_full_default_params(WHISPER_SAMPLING_GREEDY);
			wparams.n_threads = threads;
			wparams.language = language;
			wparams.print_progress = false;
			if(log || 
			   (!opt_audio_transcribe_progress_file.empty() && params)) {
				if(params) {
					params->log = log;
				}
				wparams.new_segment_callback = whisper_native_print_segment_callback;
				wparams.new_segment_callback_user_data = !opt_audio_transcribe_progress_file.empty() ? params : NULL;
			}
			if(whisper_full_parallel(ctx, wparams, pcm_data, pcm_data_samples, 1) != 0) {
				whisper_free(ctx);
				*error = "failed to process audio";
				return(false);
			}
			*language_detect = whisper_lang_str(whisper_full_lang_id(ctx));
			const int n_segments = whisper_full_n_segments(ctx);
			for(int i = 0; i < n_segments; ++i) {
				sSegment segment;
				segment.start = whisper_full_get_segment_t0(ctx, i);
				segment.stop = whisper_full_get_segment_t1(ctx, i);
				segment.text = whisper_full_get_segment_text(ctx, i);
				segments->push_back(segment);
			}
			if(log) {
				whisper_print_timings(ctx);
			}
			whisper_free(ctx);
			#else
			*error = "missing whisper library";
			return(false);
			#endif
		} else {
			if(!nativeLib.ok()) {
				*error = "initialization of the specified whisper library failed";
				return(false);
			}
			if(!log) {
				nativeLib.whisper_log_set(_whisper_native_cb_log_disable, NULL);
			}
			struct whisper_context *ctx = nativeLib.whisper_init_from_file(model);
			if(!ctx) {
				*error = "failed to initialize whisper context";
				return(false);
			}
			nativeLib.whisper_ctx_init_openvino_encoder(ctx, NULL, "cpu", NULL);
			map<string, string> next_params;
			next_params["n_threads"] = intToString(threads);
			next_params["language"] = language;
			next_params["print_progress"] = "0";
			if(nativeLib.whisper_full_parallel_params_by_ref(ctx, NULL, pcm_data, pcm_data_samples, 1, &next_params) != 0) {
				nativeLib.whisper_free(ctx);
				*error = "failed to process audio";
				return(false);
			}
			*language_detect = nativeLib.whisper_lang_str(nativeLib.whisper_full_lang_id(ctx));
			const int n_segments = nativeLib.whisper_full_n_segments(ctx);
			for(int i = 0; i < n_segments; ++i) {
				sSegment segment;
				segment.start = nativeLib.whisper_full_get_segment_t0(ctx, i);
				segment.stop = nativeLib.whisper_full_get_segment_t1(ctx, i);
				segment.text = nativeLib.whisper_full_get_segment_text(ctx, i);
				segments->push_back(segment);
			}
			if(log) {
				nativeLib.whisper_print_timings(ctx);
			}
			nativeLib.whisper_free(ctx);
		}
	} else {
		if(log) {
			cout << "max sample: " << max_sample << " - BLANK DATA" << endl;
		}
		*language_detect = strcasecmp(language, "auto") ? language : "--";
		sSegment segment;
		segment.start = 0;
		segment.stop = 0;
		segment.text = "[blank data]";
		segments->push_back(segment);
	}
	return(true);
}

static void convertJsonSegmentsToText(JsonItem *segments_item, string *text, string *segments_json) {
	if (!segments_item || segments_item->getType() != json_type_array) {
		return;
	}
	if(text) {
		text->clear();
	}
	if(segments_json) {
		*segments_json = "[";
	}
	for (size_t i = 0; i < segments_item->getLocalCount(); ++i) {
		JsonItem *segment_item = segments_item->getLocalItem(i);
		if (segment_item) {
			if(segments_json) {
				*segments_json += segment_item->getLocalValue();
			}
			if(text) {
				string segment_text = segment_item->getValue("text");
				if(!segment_text.empty()) {
					if(!text->empty()) {
						*text += " ";
					}
					*text += segment_text;
				}
			}
			if(segments_json && i < segments_item->getLocalCount() - 1) {
				*segments_json += ",";
			}
		}
	}
	if(segments_json) {
		*segments_json += "]";
	}
}

// Callback function to write response data
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool Transcribe::runWhisperRestApi(const char *wav,
								   string &rslt_language, string &rslt_text, string &rslt_segments,
								   string *error) {
	CURL *curl;
	CURLcode res;
	std::string readBuffer;

	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;
	static const char buf[] = "Expect:";

	curl_global_init(CURL_GLOBAL_ALL);

	// Add form data
	curl_formadd(&formpost,
				 &lastptr,
				 CURLFORM_COPYNAME, "audio_file",
				 CURLFORM_FILE, wav,
				 CURLFORM_END);

	curl = curl_easy_init();
	if(curl) {
		headerlist = curl_slist_append(headerlist, buf);

		curl_easy_setopt(curl, CURLOPT_URL, opt_whisper_rest_api_url.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

		if(sverb.whisper) {
			cout << "whisper rest api url: " << opt_whisper_rest_api_url << endl;
			cout << "whisper rest api file: " << wav << endl;
		}

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			if(error) {
				*error = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
			}
		} else {
			if(sverb.whisper) {
				cout << "whisper rest api response: " << readBuffer << endl;
			}

			JsonItem json;
			json.parse(readBuffer);
			
			rslt_text = json.getValue("text");
			rslt_language = json.getValue("language");
			
			JsonItem *segments_item = json.getItem("segments");
			if (segments_item && segments_item->getType() == json_type_array) {
				string text_from_segments;
				convertJsonSegmentsToText(segments_item, &text_from_segments, &rslt_segments);
				if(rslt_text.empty()) {
					rslt_text = text_from_segments;
				}
			}
		}

		curl_easy_cleanup(curl);
		curl_formfree(formpost);
		curl_slist_free_all(headerlist);
	}
	curl_global_cleanup();
	return !rslt_text.empty();
}

bool Transcribe::runWhisperRestApiStereo(const char *wav,
										  sRslt results[2],
										  string *error) {
	CURL *curl;
	CURLcode res = CURLE_FAILED_INIT;
	std::string readBuffer;
	bool success = false;

	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;
	static const char buf[] = "Expect:";

	curl_global_init(CURL_GLOBAL_ALL);

	// Add form data
	curl_formadd(&formpost,
				 &lastptr,
				 CURLFORM_COPYNAME, "audio_file",
				 CURLFORM_FILE, wav,
				 CURLFORM_END);

	curl = curl_easy_init();
	if(curl) {
		headerlist = curl_slist_append(headerlist, buf);

		curl_easy_setopt(curl, CURLOPT_URL, opt_whisper_rest_api_url.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

		if(sverb.whisper) {
			cout << "whisper rest api url (stereo mode): " << opt_whisper_rest_api_url << endl;
			cout << "whisper rest api file: " << wav << endl;
		}

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			if(error) {
				*error = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
			}
		} else {
			if(sverb.whisper) {
				cout << "whisper rest api response: " << readBuffer << endl;
			}

			// Parse the response - expected format:
			// {"detected_language":{"language":"czech","language_code":"cs","confidence":1.0},"left_channel":{...},"right_channel":{...}}
			JsonItem json;
			json.parse(readBuffer);
			
			// Get detected language info
			JsonItem *detectedLang = json.getItem("detected_language");
			string detectedLanguageCode;
			if(detectedLang) {
				detectedLanguageCode = detectedLang->getValue("language_code");
			}
			
			// Process left channel (a_*)
			JsonItem *leftChannel = json.getItem("left_channel");
			if(leftChannel) {
				results[0].language = !detectedLanguageCode.empty() ? detectedLanguageCode : leftChannel->getValue("language");
				results[0].text = leftChannel->getValue("text");
				
				JsonItem *segments_item = leftChannel->getItem("segments");
				if (segments_item && segments_item->getType() == json_type_array) {
					string text_from_segments;
					convertJsonSegmentsToText(segments_item, &text_from_segments, &results[0].segments);
					if(results[0].text.empty()) {
						results[0].text = text_from_segments;
					}
				}
			}
			
			// Process right channel (b_*)
			JsonItem *rightChannel = json.getItem("right_channel");
			if(rightChannel) {
				results[1].language = !detectedLanguageCode.empty() ? detectedLanguageCode : rightChannel->getValue("language");
				results[1].text = rightChannel->getValue("text");
				
				JsonItem *segments_item = rightChannel->getItem("segments");
				if (segments_item && segments_item->getType() == json_type_array) {
					string text_from_segments;
					convertJsonSegmentsToText(segments_item, &text_from_segments, &results[1].segments);
					if(results[1].text.empty()) {
						results[1].text = text_from_segments;
					}
				}
			}
			
			if(!leftChannel && !rightChannel) {
				if(error) {
					*error = "Expected left_channel and right_channel in JSON response for stereo mode";
				}
			} else {
				if(sverb.whisper) {
					cout << "whisper rest api stereo - parsed successfully" << endl;
					cout << "  left channel: text=" << (results[0].text.empty() ? "(empty)" : results[0].text.substr(0, 50) + "...") << endl;
					cout << "  right channel: text=" << (results[1].text.empty() ? "(empty)" : results[1].text.substr(0, 50) + "...") << endl;
				}
				success = true;
			}
		}

		curl_easy_cleanup(curl);
		curl_formfree(formpost);
		curl_slist_free_all(headerlist);
	}
	curl_global_cleanup();
	// Return true if we successfully parsed the response
	return success;
}

void Transcribe::convertSegmentsToText(list<sSegment> *segments, string *text, string *segments_json) {
	for(list<sSegment>::iterator iter = segments->begin(); iter != segments->end(); iter++) {
		if(!iter->text.empty()) {
			if(!text->empty()) {
				*text += " ";
			}
			*text += iter->text;
			if(segments_json->empty()) {
				*segments_json += "[";
			} else {
				*segments_json += ",";
			}
			JsonExport json_export;
			json_export.add("start", iter->start);
			json_export.add("stop", iter->stop);
			json_export.add("text", iter->text);
			*segments_json += json_export.getJson();
		}
	}
	if(!segments_json->empty()) {
		*segments_json += "]";
	}
}

string Transcribe::countryToLanguage(const char *country) {
	if(!country || !*country) {
		return("");
	}
	for(unsigned i = 0; i < sizeof(country_language_map) / sizeof(country_language_map[0]); i++) {
		if(!strcasecmp(country, country_language_map[i][0])) {
			return(country_language_map[i][1]);
		}
	}
	return("");
}

bool Transcribe::initNativeLib() {
	return(nativeLib.init(opt_whisper_native_lib.c_str()));
}

void Transcribe::termNativeLib() {
	return(nativeLib.term());
}

void Transcribe::saveProgress(sTranscribeWavChannelParams *params, int64_t t0, int64_t t1, const char *text) {
	if(opt_audio_transcribe_progress_file.empty()) {
		return;
	}
	lock_progress_file();
	FILE *file = fopen(opt_audio_transcribe_progress_file.c_str(), "a");
	if(file) {
		if(t0 || t1 || text) {
			fprintf(file, 
				"[CH%i,"
				int_64_format_prefix "%li,"
				int_64_format_prefix "%li,"
				"%lf] "
				"%s\n",
				params->process_channel_i + 1,
				t0, t1,
				min(100., t1 * 10 / (params->data_wav_samples / 16000. / params->channels * 1000)),
				text);
		} else {
			fprintf(file, 
				"[CH%i_END]",
				params->process_channel_i + 1);
		}
		fclose(file);
	}
	unlock_progress_file();
}

void *Transcribe::transcribeControlThread(void *) {
	u_int32_t last_activity = 0;
	u_int32_t last_activity_at = 0;
	while(true) {
		u_int32_t act_time_s = getTimeS();
		FILE *file = fopen(opt_audio_transcribe_control_file.c_str(), "r");
		if(file) {
			char row[1024] = "";
			fgets(row, sizeof(row), file);
			if(!strncmp(row, "last_activity: ", 15)) {
				u_int32_t new_activity = atoll(row + 15);
				if(new_activity != last_activity) {
					last_activity = new_activity;
					last_activity_at = act_time_s;
				}
			}
			fclose(file);
		}
		if(last_activity_at && act_time_s > last_activity_at + 10) {
			kill(transcribe_pid, 9);
		}
		sleep(2);
	}
	return(NULL);
}

void Transcribe::saveCallToDb(sCall *call) {
	extern MySqlStore *sqlStore;
	extern int opt_nocdr;
	extern sExistsColumns existsColumns;
	extern int opt_mysqlstore_max_threads_cdr;
	if(opt_nocdr || !call->isFilled()) {
		return;
	}
	if(!sqlDbSave) {
		sqlDbSave = createSqlObject();
	}
	SqlDb_row row;
	row.add_calldate(call->calltime_us, "calldate", existsColumns.cdr_audio_transcribe_calldate_ms);
	row.add(sqlEscapeString(call->callid), "fbasename");
	for(unsigned i = 0; i < call->channels_count; i++) {
		if(call->channels[i].isFilled()) {
			string column_prefix = call->channels[i].index == 1 ? "a_" : "b_";
			row.add(sqlEscapeString(call->channels[i].rslt_language), column_prefix + "language");
			row.add(sqlEscapeString(call->channels[i].rslt_text), column_prefix + "text");
			row.add(sqlEscapeString(call->channels[i].rslt_segments), column_prefix + "segments");
		}
	}
	string table = "cdr_audio_transcribe";
	if(isSqlDriver("mysql")) {
		string query_str;
		query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
			     sqlDbSave->insertQuery(table, row, false, false, true));
		static unsigned int counterSqlStore = 0;
		sqlStore->query_lock(query_str.c_str(),
				     STORE_PROC_ID_CDR,
				     opt_mysqlstore_max_threads_cdr > 1 &&
				     sqlStore->getSize(STORE_PROC_ID_CDR, 0) > 1000 ? 
				      counterSqlStore % opt_mysqlstore_max_threads_cdr : 
				      0);
		++counterSqlStore;
	} else {
		sqlDbSave->insert(table, row);
	}
}

void Transcribe::destroyCall(sCall *call) {
	if(!sverb.noaudiounlink) {
		for(unsigned i = 0; i < call->channels_count; i++) {
			unlink(call->channels[i].pcm.c_str());
			if(!call->channels[i].pcm_16.empty()) {
				unlink(call->channels[i].pcm_16.c_str());
			}
			if(!call->channels[i].wav.empty()) {
				unlink(call->channels[i].wav.c_str());
			}
		}
	}
	delete call;
}


Transcribe::sWhisperLib Transcribe::nativeLib;


void transcribePushCall(Transcribe::sCall *call) {
	if(transcribe) {
		transcribe->pushCall(call);
	}
}

void transcribeCall(Transcribe::sCall *call) {
	if(transcribe) {
		transcribe->transcribeCall(call);
	}
}

string transcribeQueueLog() {
	if(transcribe) {
		unsigned queue_size = transcribe->getQueueSize();
		if(queue_size) {
			unsigned count_threads = transcribe->getCountThreads();
			ostringstream outStr;
			outStr << queue_size << "/" << count_threads;
			return(outStr.str());
		}
	}
	return("");
}

void createTranscribe() {
	transcribe = new FILE_LINE(0) Transcribe;
	if(!opt_whisper_native_lib.empty()) {
		Transcribe::initNativeLib();
	}
}

void destroyTranscribe() {
	if(transcribe) {
		delete transcribe;
	}
	Transcribe::termNativeLib();
}
