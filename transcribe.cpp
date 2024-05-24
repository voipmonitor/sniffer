#include <sys/resource.h>
#include <sys/stat.h>

#include "calltable.h"
#include "audio_convert.h"
#include "tools.h"
#include "country_detect.h"
#include "common.h"

#include "transcribe.h"


extern int opt_audio_transcribe_threads;
extern int opt_audio_transcribe_queue_length_max;
extern string opt_whisper_model;
extern string opt_whisper_language;
extern int opt_whisper_timeout;
extern bool opt_whisper_deterministic_mode;
extern string opt_whisper_python;

static Transcribe *transcribe;
static SqlDb *sqlDbSave;

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


Transcribe::Transcribe() {
	callsMax = opt_audio_transcribe_queue_length_max;
	threadsMax = opt_audio_transcribe_threads;
	threadsTerminating = 0;
	calls_sync = 0;
	threads_sync= 0;
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

void Transcribe::pushCall(sCall *call) {
	lock_calls();
	if(calls.size() < callsMax) {
		calls.push_back(call);
		processCall();
	} else {
		destroyCall(call);
	}
	unlock_calls();
}

Transcribe::sCall *Transcribe::createTranscribeCall(Call *call, const char *chanel1_pcm, const char *chanel2_pcm, unsigned samplerate) {
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
	return(call_tr);
}

void Transcribe::processCall() {
	lock_calls();
	if(calls.size() && 
	   calls.size() > threads.size() * 2 && 
	   threads.size() < threadsMax) {
		sThread *new_hread = new FILE_LINE(0) sThread();
		threads.push_back(new_hread);
		vm_pthread_create_autodestroy("audio convert",
					      &new_hread->thread_handle, NULL, this->processThread, new_hread, __FILE__, __LINE__);
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
			if(ac.resampleRaw(&ai, call->channels[i].pcm_16.c_str(), 16000) != cAudioConvert::_rslt_ok) {
				call->channels[i].ok = false;
				call->channels[i].error = "failed resample to 16kHz";
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
		if(src.readRaw(&ai) != cAudioConvert::_rslt_ok) {
			call->channels[i].ok = false;
			call->channels[i].error = "failed convert to wav";
			continue;
		}
	}
	for(unsigned i = 0; i < call->channels_count; i++) {
		if(call->channels[i].ok) {
			string rslt_language;
			string rslt_text;
			string rslt_segments;
			string language = opt_whisper_language == "auto" ? "" : 
					  opt_whisper_language == "by_number" ? call->channels[i].language : opt_whisper_language;
			if(runWhisper(call->channels[i].wav, "", opt_whisper_python,
				      opt_whisper_model, language, opt_whisper_timeout, opt_whisper_deterministic_mode,
				      rslt_language, rslt_text, rslt_segments) &&
			   !rslt_language.empty() &&
			   !rslt_text.empty() &&
			   !rslt_segments.empty()) {
				call->channels[i].rslt_language = rslt_language;
				call->channels[i].rslt_text = rslt_text;
				call->channels[i].rslt_segments = rslt_segments;
			} else {
				call->channels[i].ok = false;
				call->channels[i].error = "failed transcribe via whisper";
			}
		}
	}
	saveCallToDb(call);
	destroyCall(call);
}

bool Transcribe::runWhisper(string wav, string script, string python,
			    string model, string language, int timeout, bool deterministic_mode,
			    string &rslt_language, string &rslt_text, string &rslt_segments) {
	bool createdWhisperScript = false;
	if(script.empty()) {
		script = createWhisperScript();
		if(script.empty()) {
			return(false);
		}
		createdWhisperScript = true;
	}
	string cmd = (!python.empty() ? python + " " + escapeShellArgument(script) : script) + " " + 
		     escapeShellArgument(wav) + " " +
		     (!model.empty() ? "--model " + escapeShellArgument(model) + " " : "") +
		     (!language.empty() ? "--language '" + escapeShellArgument(language) + "' " : "") +
		     (deterministic_mode ? "--deterministic " : "");
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
		cout << "whisper exit code: " << cmd << endl;
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
	}
	return(false);
}

string Transcribe::createWhisperScript() {
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
    parser.add_argument(\"--model\", type=str, default=\"base\", help=\"Whisper model to use (e.g., tiny, base, small, medium, large)\")\n\
    parser.add_argument(\"--language\", type=str, help=\"Language code (ISO 639-1) for the transcription\")\n\
    parser.add_argument(\"--deterministic\", action='store_true', help=\"Enable deterministic behavior\")\n\
\n\
    args = parser.parse_args()\n\
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
	for(unsigned i = 0; i < call->channels_count; i++) {
		unlink(call->channels[i].pcm.c_str());
		if(!call->channels[i].pcm_16.empty()) {
			unlink(call->channels[i].pcm_16.c_str());
		}
		if(!call->channels[i].wav.empty()) {
			unlink(call->channels[i].wav.c_str());
		}
	}
	delete call;
}


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
		unsigned count_threads = transcribe->getCountThreads();
		if(queue_size || count_threads) {
			ostringstream outStr;
			outStr << queue_size << "/" << count_threads;
			return(outStr.str());
		}
	}
	return("");
}

void createTranscribe() {
	transcribe = new FILE_LINE(0) Transcribe;
}

void destroyTranscribe() {
	if(transcribe) {
		delete transcribe;
	}
}
