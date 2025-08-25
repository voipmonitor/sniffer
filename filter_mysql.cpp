#include <syslog.h>
#include <string.h>
#include "voipmonitor.h"

#include "filter_mysql.h"
#include "calltable.h"
#include "odbc.h"
#include "sql_db.h"
#include <math.h>
#include <vector>


extern bool selectSensorsContainSensorId(string select_sensors);


using namespace std;

extern int opt_nocdr;


bool isStringNull(string &str) {
	return(str == "" || str == "\\N");
}

string filter_base::_string(SqlDb_row *sqlRow, map<string, string> *row, const char *column) {
	return(sqlRow ?
		(*sqlRow)[column].c_str() :
		(*row)[column].c_str());
}

bool filter_base::_value_is_null(SqlDb_row *sqlRow, map<string, string> *row, const char *column) {
	return(sqlRow ?
		sqlRow->isNull(column) :
		isStringNull((*row)[column]));
}

int filter_base::_value(SqlDb_row *sqlRow, map<string, string> *row, const char *column) {
	return(atoi(sqlRow ?
		     (*sqlRow)[column].c_str() :
		     (*row)[column].c_str()));
}

void filter_base::_loadBaseDataRow(SqlDb_row *sqlRow, map<string, string> *row, filter_db_row_base *baseRow) {
	baseRow->direction = _value_is_null(sqlRow, row, "direction") ? 0 : _value(sqlRow, row, "direction");
	baseRow->rtp = _value_is_null(sqlRow, row, "rtp") ? -1 : _value(sqlRow, row, "rtp");
	baseRow->rtp_video = _value_is_null(sqlRow, row, "rtp_video") ? -1 : _value(sqlRow, row, "rtp_video");
	baseRow->mrcp = _value_is_null(sqlRow, row, "mrcp") ? -1 : _value(sqlRow, row, "mrcp");
	baseRow->rtcp = _value_is_null(sqlRow, row, "rtcp") ? -1 : _value(sqlRow, row, "rtcp");
	baseRow->sip = _value_is_null(sqlRow, row, "sip") ? -1 : _value(sqlRow, row, "sip");
	baseRow->reg = _value_is_null(sqlRow, row, "register") ? -1 : _value(sqlRow, row, "register");
	baseRow->dtmf = _value_is_null(sqlRow, row, "dtmf") ? -1 : _value(sqlRow, row, "dtmf");
	baseRow->graph = _value_is_null(sqlRow, row, "graph") ? -1 : _value(sqlRow, row, "graph");
	baseRow->wav = _value_is_null(sqlRow, row, "wav") ? -1 : _value(sqlRow, row, "wav");
	baseRow->audio_transcribe = _value_is_null(sqlRow, row, "audio_transcribe") ? -1 : _value(sqlRow, row, "audio_transcribe");
	baseRow->audiograph = _value_is_null(sqlRow, row, "audiograph") ? -1 : _value(sqlRow, row, "audiograph");
	baseRow->skip = _value_is_null(sqlRow, row, "skip") ? -1 : _value(sqlRow, row, "skip");
	baseRow->script = _value_is_null(sqlRow, row, "script") ? -1 : _value(sqlRow, row, "script");
	baseRow->mos_lqo = _value_is_null(sqlRow, row, "mos_lqo") ? -1 : _value(sqlRow, row, "mos_lqo");
	baseRow->hide_message = _value_is_null(sqlRow, row, "hide_message") ? -1 : _value(sqlRow, row, "hide_message");
	baseRow->spool_2 = _value_is_null(sqlRow, row, "spool_2") ? -1 : _value(sqlRow, row, "spool_2");
	baseRow->options = _value_is_null(sqlRow, row, "options") ? -1 : _value(sqlRow, row, "options");
	baseRow->notify = _value_is_null(sqlRow, row, "notify") ? -1 : _value(sqlRow, row, "notify");
	baseRow->subscribe = _value_is_null(sqlRow, row, "subscribe") ? -1 : _value(sqlRow, row, "subscribe");
	baseRow->natalias = _string(sqlRow, row, "natalias");
	baseRow->natalias_inheritance = _value(sqlRow, row, "natalias_inheritance");
}

void filter_base::loadBaseDataRow(SqlDb_row *sqlRow, filter_db_row_base *baseRow) {
	_loadBaseDataRow(sqlRow, NULL, baseRow);
}

void filter_base::loadBaseDataRow(map<string, string> *row, filter_db_row_base *baseRow) {
	_loadBaseDataRow(NULL, row, baseRow);
}

u_int64_t filter_base::getFlagsFromBaseData(filter_db_row_base *baseRow, u_int32_t *global_flags) {
	u_int64_t flags = 0;
	
	if(baseRow->rtp == 1)			flags |= CAPT_FLAG(_CAPT_BIT_RTP_ALL);
	else if(baseRow->rtp == 2)		flags |= CAPT_FLAG(_CAPT_BIT_RTP_HEADER);
	else if(baseRow->rtp == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NORTP);
	
	if(baseRow->rtp_video == 1)		flags |= CAPT_FLAG(_CAPT_BIT_RTP_VIDEO_ALL);
	else if(baseRow->rtp_video == 2)	flags |= CAPT_FLAG(_CAPT_BIT_RTP_VIDEO_HEADER);
	else if(baseRow->rtp_video == 3)	flags |= CAPT_FLAG(_CAPT_BIT_RTP_VIDEO_CDR_ONLY);
	else if(baseRow->rtp_video == 0)	flags |= CAPT_FLAG(_CAPT_BIT_NORTP_VIDEO);
	
	if(baseRow->mrcp == 1)			{ flags |= CAPT_FLAG(_CAPT_BIT_MRCP); *global_flags |= cFilters::_gf_mrcp; }
	else if(baseRow->mrcp == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOMRCP);
	
	if(baseRow->rtcp == 1)			flags |= CAPT_FLAG(_CAPT_BIT_RTCP);
	else if(baseRow->rtcp == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NORTCP);
	
	if(baseRow->sip == 1)			flags |= CAPT_FLAG(_CAPT_BIT_SIP);
	else if(baseRow->sip == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOSIP);
	
	if (baseRow->reg == 0)			flags |= CAPT_FLAG(_CAPT_BIT_NOREGISTER_DB) | CAPT_FLAG(_CAPT_BIT_NOREGISTER_PCAP);
	else if (baseRow->reg == 1)		flags |= CAPT_FLAG(_CAPT_BIT_REGISTER_DB) | CAPT_FLAG(_CAPT_BIT_REGISTER_PCAP);
	else if (baseRow->reg == 2)		flags |= CAPT_FLAG(_CAPT_BIT_REGISTER_DB) | CAPT_FLAG(_CAPT_BIT_NOREGISTER_PCAP);
	else if (baseRow->reg == 3)		flags |= CAPT_FLAG(_CAPT_BIT_NOREGISTER_DB) | CAPT_FLAG(_CAPT_BIT_REGISTER_PCAP);

	if(baseRow->dtmf == 1)			flags |= CAPT_FLAG(_CAPT_BIT_DTMF_DB) | CAPT_FLAG(_CAPT_BIT_DTMF_PCAP);
	else if(baseRow->dtmf == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NODTMF_DB) | CAPT_FLAG(_CAPT_BIT_NODTMF_PCAP);
	else if(baseRow->dtmf == 2)		flags |= CAPT_FLAG(_CAPT_BIT_DTMF_DB) | CAPT_FLAG(_CAPT_BIT_NODTMF_PCAP);
	else if(baseRow->dtmf == 3)		flags |= CAPT_FLAG(_CAPT_BIT_DTMF_PCAP) | CAPT_FLAG(_CAPT_BIT_NODTMF_DB);
	
	if(baseRow->graph == 1)			flags |= CAPT_FLAG(_CAPT_BIT_GRAPH);
	else if(baseRow->graph == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOGRAPH);
	
	if(baseRow->wav == 1)			flags |= CAPT_FLAG(_CAPT_BIT_AUDIO);
	else if(baseRow->wav == 2)		flags |= CAPT_FLAG(_CAPT_BIT_AUDIO_WAV);
	else if(baseRow->wav == 3)		flags |= CAPT_FLAG(_CAPT_BIT_AUDIO_OGG);
	else if(baseRow->wav == 4)		flags |= CAPT_FLAG(
								   #if HAVE_LIBLAME && HAVE_LIBMPG123
								   _CAPT_BIT_AUDIO_MP3
								   #else
								   _CAPT_BIT_AUDIO_OGG
								   #endif
								   );
	else if(baseRow->wav == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOWAV);
	
	if(baseRow->audio_transcribe == 1)	flags |= CAPT_FLAG(_CAPT_BIT_AUDIO_TRANSCRIBE);
	else if(baseRow->audio_transcribe == 0)	flags |= CAPT_FLAG(_CAPT_BIT_NO_AUDIO_TRANSCRIBE);
	
	if(baseRow->audiograph == 1)		flags |= CAPT_FLAG(_CAPT_BIT_AUDIOGRAPH);
	else if(baseRow->audiograph == 0)	flags |= CAPT_FLAG(_CAPT_BIT_NO_AUDIOGRAPH);
	
	if(baseRow->skip == 1)			flags |= CAPT_FLAG(_CAPT_BIT_SKIP);
	else if(baseRow->skip == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOSKIP);
	
	if(baseRow->script == 1)		flags |= CAPT_FLAG(_CAPT_BIT_SCRIPT);
	else if(baseRow->script == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOSCRIPT);
	
	if(baseRow->mos_lqo == 1)		flags |= CAPT_FLAG(_CAPT_BIT_AMOSLQO);
	else if(baseRow->mos_lqo == 2)		flags |= CAPT_FLAG(_CAPT_BIT_BMOSLQO);
	else if(baseRow->mos_lqo == 3)		flags |= CAPT_FLAG(_CAPT_BIT_ABMOSLQO);
	else if(baseRow->mos_lqo == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOMOSLQO);
	
	if(baseRow->hide_message == 1)		flags |= CAPT_FLAG(_CAPT_BIT_HIDEMSG);
	else if(baseRow->hide_message == 0)	flags |= CAPT_FLAG(_CAPT_BIT_SHOWMSG);
	
	if(baseRow->spool_2 == 1)		flags |= CAPT_FLAG(_CAPT_BIT_SPOOL_2_SET);
	else if(baseRow->spool_2 == 0)		flags |= CAPT_FLAG(_CAPT_BIT_SPOOL_2_UNSET);

	if (baseRow->options == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOOPTIONS_DB) | CAPT_FLAG(_CAPT_BIT_NOOPTIONS_PCAP);
	else if (baseRow->options == 1)		flags |= CAPT_FLAG(_CAPT_BIT_OPTIONS_DB) | CAPT_FLAG(_CAPT_BIT_OPTIONS_PCAP);
	else if (baseRow->options == 2)		flags |= CAPT_FLAG(_CAPT_BIT_OPTIONS_DB) | CAPT_FLAG(_CAPT_BIT_NOOPTIONS_PCAP);
	else if (baseRow->options == 3)		flags |= CAPT_FLAG(_CAPT_BIT_NOOPTIONS_DB) | CAPT_FLAG(_CAPT_BIT_OPTIONS_PCAP);

	if (baseRow->notify == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NONOTIFY_DB) | CAPT_FLAG(_CAPT_BIT_NONOTIFY_PCAP);
	else if (baseRow->notify == 1)		flags |= CAPT_FLAG(_CAPT_BIT_NOTIFY_DB) | CAPT_FLAG(_CAPT_BIT_NOTIFY_PCAP);
	else if (baseRow->notify == 2)		flags |= CAPT_FLAG(_CAPT_BIT_NOTIFY_DB) | CAPT_FLAG(_CAPT_BIT_NONOTIFY_PCAP);
	else if (baseRow->notify == 3)		flags |= CAPT_FLAG(_CAPT_BIT_NONOTIFY_DB) | CAPT_FLAG(_CAPT_BIT_NOTIFY_PCAP);

	if (baseRow->subscribe == 0)		flags |= CAPT_FLAG(_CAPT_BIT_NOSUBSCRIBE_DB) | CAPT_FLAG(_CAPT_BIT_NOSUBSCRIBE_PCAP);
	else if (baseRow->subscribe == 1)	flags |= CAPT_FLAG(_CAPT_BIT_SUBSCRIBE_DB) | CAPT_FLAG(_CAPT_BIT_SUBSCRIBE_PCAP);
	else if (baseRow->subscribe == 2)	flags |= CAPT_FLAG(_CAPT_BIT_SUBSCRIBE_DB) | CAPT_FLAG(_CAPT_BIT_NOSUBSCRIBE_PCAP);
	else if (baseRow->subscribe == 3)	flags |= CAPT_FLAG(_CAPT_BIT_NOSUBSCRIBE_DB) | CAPT_FLAG(_CAPT_BIT_SUBSCRIBE_PCAP);

	return(flags);
}

void filter_base::parseNatAliases(filter_db_row_base *baseRow, nat_aliases_t **nat_aliases) {
	if(!baseRow->natalias.empty()) {
		*nat_aliases = new FILE_LINE(0) nat_aliases_t;
		vector<string> nat_aliases_str = split(baseRow->natalias, '\n');
		for(unsigned i = 0; i < nat_aliases_str.size(); i++) {
			vmIP ip_nat[2];
			const char *ip_nat_2_str;
			if(ip_nat[0].setFromString(nat_aliases_str[i].c_str(), &ip_nat_2_str)) {
				while(*ip_nat_2_str == ' ' || *ip_nat_2_str == '\t' || *ip_nat_2_str == ':' || *ip_nat_2_str == '=') {
					++ip_nat_2_str;
				}
				if(ip_nat[1].setFromString(ip_nat_2_str, NULL)) {
					(**nat_aliases)[ip_nat[0]] = ip_nat[1];
				}
			}
		}
		if(!(*nat_aliases)->size()) {
			delete *nat_aliases;
			*nat_aliases = NULL;
		}
	}
}

void filter_base::setCallFlagsFromFilterFlags(volatile unsigned long int *callFlags, u_int64_t filterFlags, bool reconfigure) {
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SIP))			*callFlags |= FLAG_SAVESIP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOSIP))			*callFlags &= ~FLAG_SAVESIP;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_RTP_ALL))			{*callFlags |= FLAG_SAVERTP; *callFlags &= ~FLAG_SAVERTPHEADER;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_RTP_HEADER))		{*callFlags |= FLAG_SAVERTPHEADER; *callFlags &= ~FLAG_SAVERTP;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NORTP)) 			{*callFlags &= ~FLAG_SAVERTP; *callFlags &= ~FLAG_SAVERTPHEADER;}
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_RTP_VIDEO_ALL))		{*callFlags |= (FLAG_SAVERTP_VIDEO | FLAG_PROCESSING_RTP_VIDEO); *callFlags &= ~FLAG_SAVERTP_VIDEO_HEADER;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_RTP_VIDEO_HEADER))		{*callFlags |= (FLAG_SAVERTP_VIDEO_HEADER | FLAG_PROCESSING_RTP_VIDEO); *callFlags &= ~FLAG_SAVERTP_VIDEO;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_RTP_VIDEO_CDR_ONLY))	{*callFlags |= FLAG_PROCESSING_RTP_VIDEO; *callFlags &= ~(FLAG_SAVERTP_VIDEO | FLAG_SAVERTP_VIDEO_HEADER);}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NORTP_VIDEO)) 		{*callFlags &= ~(FLAG_SAVERTP_VIDEO | FLAG_SAVERTP_VIDEO_HEADER | FLAG_PROCESSING_RTP_VIDEO);}
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_MRCP))			*callFlags |= FLAG_SAVEMRCP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOMRCP))			*callFlags &= ~FLAG_SAVEMRCP;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_RTCP))			*callFlags |= FLAG_SAVERTCP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NORTCP))			*callFlags &= ~FLAG_SAVERTCP;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_REGISTER_DB))		*callFlags |= FLAG_SAVEREGISTERDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOREGISTER_DB))		*callFlags &= ~FLAG_SAVEREGISTERDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_REGISTER_PCAP))		*callFlags |= FLAG_SAVEREGISTERPCAP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOREGISTER_PCAP))		*callFlags &= ~FLAG_SAVEREGISTERPCAP;

	if(filterFlags & CAPT_FLAG(_CAPT_BIT_DTMF_DB))			*callFlags |= FLAG_SAVEDTMFDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NODTMF_DB))		*callFlags &= ~FLAG_SAVEDTMFDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_DTMF_PCAP))		*callFlags |= FLAG_SAVEDTMFPCAP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NODTMF_PCAP))		*callFlags &= ~FLAG_SAVEDTMFPCAP;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_AUDIO))			*callFlags |= FLAG_SAVEAUDIO;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_AUDIO_WAV))		{*callFlags &= ~(FLAG_FORMATAUDIO_OGG|FLAG_SAVEAUDIO_MP3); *callFlags |= FLAG_SAVEAUDIO_WAV|FLAG_SAVEAUDIO;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_AUDIO_OGG))		{*callFlags &= ~(FLAG_FORMATAUDIO_WAV|FLAG_SAVEAUDIO_MP3); *callFlags |= FLAG_SAVEAUDIO_OGG|FLAG_SAVEAUDIO;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_AUDIO_MP3))		{*callFlags &= ~(FLAG_FORMATAUDIO_WAV|FLAG_SAVEAUDIO_OGG); *callFlags |= FLAG_SAVEAUDIO_MP3|FLAG_SAVEAUDIO;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOWAV))			*callFlags &= ~FLAG_SAVEAUDIO;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_AUDIO_TRANSCRIBE))		*callFlags |= FLAG_AUDIOTRANSCRIBE;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NO_AUDIO_TRANSCRIBE))	*callFlags &= ~FLAG_AUDIOTRANSCRIBE;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_AUDIOGRAPH))		*callFlags |= FLAG_SAVEAUDIOGRAPH;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NO_AUDIOGRAPH))		*callFlags &= ~FLAG_SAVEAUDIOGRAPH;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_GRAPH))			*callFlags |= FLAG_SAVEGRAPH;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOGRAPH))			*callFlags &= ~FLAG_SAVEGRAPH;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SKIP))			*callFlags |= FLAG_SKIPCDR;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOSKIP))			*callFlags &= ~FLAG_SKIPCDR;
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SCRIPT))			*callFlags |= FLAG_RUNSCRIPT;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOSCRIPT))			*callFlags &= ~FLAG_RUNSCRIPT;

	if(filterFlags & CAPT_FLAG(_CAPT_BIT_AMOSLQO))			{*callFlags |= FLAG_RUNAMOSLQO; *callFlags &= ~FLAG_RUNBMOSLQO;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_BMOSLQO))			{*callFlags |= FLAG_RUNBMOSLQO; *callFlags &= ~FLAG_RUNAMOSLQO;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_ABMOSLQO))			{*callFlags |= FLAG_RUNAMOSLQO|FLAG_RUNBMOSLQO;}
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOMOSLQO)) 		{*callFlags &= ~FLAG_RUNAMOSLQO; *callFlags &= ~FLAG_RUNBMOSLQO;}
	
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_HIDEMSG))			*callFlags |= FLAG_HIDEMESSAGE;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SHOWMSG))			*callFlags &= ~FLAG_HIDEMESSAGE;
	
	if(!reconfigure) {
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SPOOL_2_SET))		*callFlags |= FLAG_USE_SPOOL_2;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SPOOL_2_UNSET))		*callFlags &= ~FLAG_USE_SPOOL_2;
	}

	if(filterFlags & CAPT_FLAG(_CAPT_BIT_OPTIONS_DB))		*callFlags |= FLAG_SAVEOPTIONSDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOOPTIONS_DB))		*callFlags &= ~FLAG_SAVEOPTIONSDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_OPTIONS_PCAP))		*callFlags |= FLAG_SAVEOPTIONSPCAP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOOPTIONS_PCAP))		*callFlags &= ~FLAG_SAVEOPTIONSPCAP;

	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOTIFY_DB))		*callFlags |= FLAG_SAVENOTIFYDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NONOTIFY_DB))		*callFlags &= ~FLAG_SAVENOTIFYDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOTIFY_PCAP))		*callFlags |= FLAG_SAVENOTIFYPCAP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NONOTIFY_PCAP))		*callFlags &= ~FLAG_SAVENOTIFYPCAP;

	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SUBSCRIBE_DB))		*callFlags |= FLAG_SAVESUBSCRIBEDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOSUBSCRIBE_DB))		*callFlags &= ~FLAG_SAVESUBSCRIBEDB;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_SUBSCRIBE_PCAP))		*callFlags |= FLAG_SAVESUBSCRIBEPCAP;
	if(filterFlags & CAPT_FLAG(_CAPT_BIT_NOSUBSCRIBE_PCAP))		*callFlags &= ~FLAG_SAVESUBSCRIBEPCAP;
}

/* IPfilter class */

// constructor
IPfilter::IPfilter() {
	first_node = NULL;
	count = 0;
	reload_do = false;
};

// destructor
IPfilter::~IPfilter() {
	t_node *node = first_node;
	while(node != NULL) {
		t_node *node_next = node->next;
		delete node;
		node = node_next;
	}
};

void IPfilter::load(u_int32_t *global_flags, SqlDb *sqlDb) {
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool existsSensorsTable = sqlDb->existsTable("filter_ip_sensors");
	sqlDb->query(string("SELECT filter_ip.*") +
		     (existsSensorsTable ? 
		       ",(select group_concat(coalesce(sensor_id, -2)) \
  			  from filter_ip_sensors \
			  where filter_ip_id = filter_ip.id) as sensors_id" :
		       "") +
		     " FROM filter_ip ORDER BY ip desc, mask desc");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		if(!(!existsSensorsTable || selectSensorsContainSensorId(row["sensors_id"]))) {
			continue;
		}
		count++;
		db_row* filterRow = new FILE_LINE(4001) db_row;
		filterRow->ip.setIP(&row, "ip");
		filterRow->mask = atoi(row["mask"].c_str());
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	t_node *node;
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		node = new FILE_LINE(0) t_node;
		node->direction = vectDbRow[i].direction;
		node->next = NULL;
		node->network = vectDbRow[i].ip.network(vectDbRow[i].mask);
		node->mask = vectDbRow[i].mask;
		node->flags = this->getFlagsFromBaseData(&vectDbRow[i], global_flags);
		this->parseNatAliases(&vectDbRow[i], &node->nat_aliases);
		node->nat_aliases_inheritance = vectDbRow[i].natalias_inheritance;

		// add node to the first position
		node->next = first_node;
		first_node = node;
	}
};

int IPfilter::_add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, vmIP saddr, vmIP daddr, bool reconfigure) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}

	int last_mask = 0;
	char found = 0;
	map<int, t_node*> nat_aliases_node_mask;
	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {
		if((!node->network.isSet() && !node->mask) ||
		   ((node->direction == 0 or node->direction == 2) and (daddr.network(node->mask) == node->network)) || 
		   ((node->direction == 0 or node->direction == 1) and (saddr.network(node->mask) == node->network))) {
			int mask = node->network.isSet() && !node->mask ? node->network.bits() : node->mask;
			if(mask < last_mask) {
				if(node->nat_aliases) {
					nat_aliases_node_mask[node->mask] = node;
				}
				continue;
			}
			last_mask = mask;
			this->setCallFlagsFromFilterFlags(flags, node->flags, reconfigure);
			if(node->nat_aliases) {
				nat_aliases_node_mask[mask] = node;
			}
			found = 1;
		}
	}
	if(nat_aliases_node_mask.size()) {
		unsigned counter = 0;
		for(map<int, t_node*>::reverse_iterator iter = nat_aliases_node_mask.rbegin(); iter != nat_aliases_node_mask.rend(); iter++) {
			if(!counter || iter->second->nat_aliases_inheritance) {
				comb_nat_aliases(iter->second->nat_aliases, nat_aliases);
			}
			++counter;
		}
	}
	return found;
}

void IPfilter::dump2man(ostringstream &oss) {
	t_node *node;
	lock();
	for(node = filter_active->first_node; node != NULL; node = node->next) {
		oss << "ip[" << node->network.getString() << "/" << node->mask << "] direction[" << node->direction << "] flags[0x" << hex << node->flags << "]" << endl;
	}
	unlock();
}

int IPfilter::add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, vmIP saddr, vmIP daddr, bool reconfigure) {
	int rslt = 0;
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(flags, nat_aliases, saddr, daddr, reconfigure);
	}
	unlock();
	return(rslt);
}

void IPfilter::loadActive(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4002) IPfilter();
	filter_active->load(global_flags, sqlDb);
	unlock();
}

void IPfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void IPfilter::prepareReload(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4003) IPfilter;
	filter_reload->load(global_flags, sqlDb);
	reload_do = true;
	syslog(LOG_NOTICE, "IPfilter::prepareReload");
	unlock_reload();
}

void IPfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		if(reload_do) {
			lock();
			delete filter_active;
			filter_active = filter_reload;
			unlock();
			filter_reload = NULL;
			reload_do = false;
			syslog(LOG_NOTICE, "IPfilter::applyReload");
		}
		unlock_reload();
	}
}

IPfilter *IPfilter::filter_active = NULL;
IPfilter *IPfilter::filter_reload = NULL;
volatile bool IPfilter::reload_do = 0;
volatile int IPfilter::_sync = 0;
volatile int IPfilter::_sync_reload = 0;

/* TELNUMfilter class */

// constructor
TELNUMfilter::TELNUMfilter() {
        first_node = new FILE_LINE(0) t_node_tel;
        first_node->payload = NULL;
        for(int i = 0; i < 256; i++) {
                first_node->nodes[i] = NULL;
	}
	count = 0;
	reload_do = false;
};

// destructor
TELNUMfilter::~TELNUMfilter() {
        // je nutne uvolnit t_payload strukturu a t_node
        // algoritmus musi projit strom a postupne odmazavat za pomoci fronty
        // (prohledavani do sirky)
        //
        // do fronty se prida first_node
        // DO WHILE (dokud neni prazdna fronta )
        //      pro kazdy prvek se projdou naslednici a zaradi se nakonec fronty
        //      zpracovavany t_node se odstrani ze predu fronty a uvolni se pamet
        // ENDWHILE

        deque<t_node_tel*> fronta;
        fronta.push_back(first_node);
        t_node_tel *node;
        while( !fronta.empty() ) {
                node = fronta.front();
                if(node->payload) {
                        // nektera cisla nemaji payload
                        delete(node->payload);
                }

                for(int i = 0; i < 256; i++) {
                        if(node->nodes[i]) {
                                // vsichni nenulovi naslednici zaradime na konec fronty
                                fronta.push_back(node->nodes[i]);
                        }
                }
                //otce muzeme vymazat z fronty a nasledne dealokovat pamet
                fronta.pop_front();
                delete(node);
        }
};

void TELNUMfilter::add_payload(t_payload *payload) {
	t_node_tel *tmp = first_node;

	for(unsigned int i = 0; i < strlen(payload->prefix); i++) {
		if(!tmp->nodes[(int)payload->prefix[i]]) {
			t_node_tel *node = new FILE_LINE(0) t_node_tel;
			node->payload = NULL;
			for(int j = 0; j < 256; j++) {
				node->nodes[j] = NULL;
			}
			tmp->nodes[(int)payload->prefix[i]] = node;
		}
		tmp = tmp->nodes[(int)payload->prefix[i]];      // shift

	}

	tmp->payload = payload;
};


void TELNUMfilter::load(u_int32_t *global_flags, SqlDb *sqlDb) {
	this->loadFile(global_flags);
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool existsSensorsTable = sqlDb->existsTable("filter_telnum_sensors");
	sqlDb->query(string("SELECT filter_telnum.*") +
		     (existsSensorsTable ? 
		       ",(select group_concat(coalesce(sensor_id, -2)) \
  			  from filter_telnum_sensors \
			  where filter_telnum_id = filter_telnum.id) as sensors_id" :
		       "") +
		     " FROM filter_telnum");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		if(!(!existsSensorsTable || selectSensorsContainSensorId(row["sensors_id"]))) {
			continue;
		}
		count++;
		db_row* filterRow = new FILE_LINE(0) db_row;
		strcpy_null_term(filterRow->prefix, trim_str(row["prefix"]).c_str());
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		t_payload *np = new FILE_LINE(0) t_payload;
		np->direction = vectDbRow[i].direction;
		strcpy_null_term(np->prefix, vectDbRow[i].prefix);
		np->flags = this->getFlagsFromBaseData(&vectDbRow[i], global_flags);
		this->parseNatAliases(&vectDbRow[i], &np->nat_aliases);
		add_payload(np);
	}
};

void TELNUMfilter::loadFile(u_int32_t *global_flags) {
	extern char opt_capture_rules_telnum_file[1024];
	if(is_sender() || is_client_packetbuffer_sender() || !opt_capture_rules_telnum_file[0]) {
		return;
	}
	cCsv csv;
	csv.setFirstRowContainFieldNames();
	csv.load(opt_capture_rules_telnum_file);
	unsigned rowsCount = csv.getRowsCount();
	vector<db_row> vectDbRow;
	for(unsigned i = 1; i <= rowsCount; i++) {
		map<string, string> row;
		csv.getRow(i, &row);
		count++;
		db_row* filterRow = new FILE_LINE(0) db_row;
		strcpy_null_term(filterRow->prefix, trim_str(row["prefix"]).c_str());
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	for(size_t i = 0; i < vectDbRow.size(); ++i) {
		t_payload *np = new FILE_LINE(0) t_payload;
		np->direction = vectDbRow[i].direction;
		strcpy_null_term(np->prefix, vectDbRow[i].prefix);
		np->flags = this->getFlagsFromBaseData(&vectDbRow[i], global_flags);
		this->parseNatAliases(&vectDbRow[i], &np->nat_aliases);
		add_payload(np);
	}
}

int TELNUMfilter::_add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *telnum_src, const char *telnum_dst, bool reconfigure) {

	if (this->count == 0) {
		// no filters, return 
		return 0;
	}
	
	unsigned found_length = 0;
	u_int64_t found_flags = 0;
	nat_aliases_t *found_nat_aliases = NULL;
	for(int src_dst = 1; src_dst <= 2; src_dst++) {
		const char *telnum = src_dst == 1 ? telnum_src : telnum_dst;
		unsigned telnum_length = strlen(telnum);
		t_node_tel *node = first_node;
		for(unsigned int i = 0; i < telnum_length; i++) {
			unsigned char checkChar = telnum[i];
			if(checkChar == '%' && !strncmp(telnum + i, "%23", 3)) {
				checkChar = '#';
				i += 2;
			}
			if(!node->nodes[checkChar]) {
				break;
			}
			node = node->nodes[checkChar];
			if(node && node->payload &&
			   (node->payload->direction == 0 ||
			    node->payload->direction == src_dst) &&
			   (i + 1) > found_length) {
				found_length = i + 1;
				found_flags = node->payload->flags;
				found_nat_aliases = node->payload->nat_aliases;
			}
		}
	}
	if(found_length > 0) {
		this->setCallFlagsFromFilterFlags(flags, found_flags, reconfigure);
		comb_nat_aliases(found_nat_aliases, nat_aliases);
	}
	return(found_length > 0);
}

void TELNUMfilter::dump2man(ostringstream &oss, t_node_tel *node) {
	if(!node) {
		lock();
		node = filter_active->first_node;
	}
	if(node->payload) {
		oss << "prefix[" << node->payload->prefix << "] direction[" << node->payload->direction << "] flags[0x" << hex << node->payload->flags << "]" << endl;
	}
	for(int i = 0; i < 256; i++) {
		if(node->nodes[i]) {
			dump2man(oss, node->nodes[i]);
		}
	}
	if (node == filter_active->first_node)
		unlock();
}

int TELNUMfilter::add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *telnum_src, const char *telnum_dst, bool reconfigure) {
	int rslt = 0;
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(flags, nat_aliases, telnum_src, telnum_dst, reconfigure);
	}
	unlock();
	return(rslt);
}

void TELNUMfilter::loadActive(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4004) TELNUMfilter();
	filter_active->load(global_flags, sqlDb);
	unlock();
}

void TELNUMfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void TELNUMfilter::prepareReload(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4005) TELNUMfilter;
	filter_reload->load(global_flags, sqlDb);
	reload_do = true;
	syslog(LOG_NOTICE, "TELNUMfilter::prepareReload");
	unlock_reload();
}

void TELNUMfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		if(reload_do) {
			lock();
			delete filter_active;
			filter_active = filter_reload;
			unlock();
			filter_reload = NULL;
			reload_do = false; 
			syslog(LOG_NOTICE, "TELNUMfilter::applyReload");
		}
		unlock_reload();
	}
}

TELNUMfilter *TELNUMfilter::filter_active = NULL;
TELNUMfilter *TELNUMfilter::filter_reload = NULL;
volatile bool TELNUMfilter::reload_do = 0;
volatile int TELNUMfilter::_sync = 0;
volatile int TELNUMfilter::_sync_reload = 0;

/* DOMAINfilter class */

// constructor
DOMAINfilter::DOMAINfilter() {
	first_node = NULL;
	count = 0;
	reload_do = false;
};

// destructor
DOMAINfilter::~DOMAINfilter() {
	t_node *node = first_node;
	while(node != NULL) {
		t_node *node_next = node->next;
		delete node;
		node = node_next;
	}
};

void DOMAINfilter::load(u_int32_t *global_flags, SqlDb *sqlDb) {
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool existsSensorsTable = sqlDb->existsTable("filter_domain_sensors");
	sqlDb->query(string("SELECT filter_domain.*") +
		     (existsSensorsTable ? 
		       ",(select group_concat(coalesce(sensor_id, -2)) \
  			  from filter_domain_sensors \
			  where filter_domain_id = filter_domain.id) as sensors_id" :
		       "") +
		     " FROM filter_domain");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		if(!(!existsSensorsTable || selectSensorsContainSensorId(row["sensors_id"]))) {
			continue;
		}
		count++;
		db_row* filterRow = new FILE_LINE(4006) db_row;
		filterRow->domain = trim_str(row["domain"]);
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	t_node *node;
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		node = new FILE_LINE(0) t_node;
		node->direction = vectDbRow[i].direction;
		node->next = NULL;
		node->domain = vectDbRow[i].domain;
		node->flags = this->getFlagsFromBaseData(&vectDbRow[i], global_flags);
		this->parseNatAliases(&vectDbRow[i], &node->nat_aliases);

		// add node to the first position
		node->next = first_node;
		first_node = node;
	}
};

int
DOMAINfilter::_add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *domain_src, const char *domain_dst, bool reconfigure) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}

	t_node *node;
	for(node = first_node; node != NULL; node = node->next) {

		if(((node->direction == 0 or node->direction == 2) and (domain_dst == node->domain)) || 
			((node->direction == 0 or node->direction == 1) and (domain_src == node->domain))) {
			this->setCallFlagsFromFilterFlags(flags, node->flags, reconfigure);
			comb_nat_aliases(node->nat_aliases, nat_aliases);
			return 1;
		}
	}

	return 0;
}

void DOMAINfilter::dump2man(ostringstream &oss) {
	t_node *node;
	lock();
	for(node = filter_active->first_node; node != NULL; node = node->next) {
		oss << "domain[" << node->domain << "] direction[" << node->direction << "] flags[0x" << hex << node->flags << "]" << endl;
	}
	unlock();
}

int DOMAINfilter::add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *domain_src, const char *domain_dst, bool reconfigure) {
	int rslt = 0;
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(flags, nat_aliases, domain_src, domain_dst);
	}
	unlock();
	return(rslt);
}

void DOMAINfilter::loadActive(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4007) DOMAINfilter();
	filter_active->load(global_flags, sqlDb);
	unlock();
}

void DOMAINfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void DOMAINfilter::prepareReload(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4008) DOMAINfilter;
	filter_reload->load(global_flags, sqlDb);
	reload_do = true;
	syslog(LOG_NOTICE, "DOMAINfilter::prepareReload");
	unlock_reload();
}

void DOMAINfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		if(reload_do) {
			lock();
			delete filter_active;
			filter_active = filter_reload;
			unlock();
			filter_reload = NULL;
			reload_do = false; 
			syslog(LOG_NOTICE, "DOMAINfilter::applyReload");
		}
		unlock_reload();
	}
}

DOMAINfilter *DOMAINfilter::filter_active = NULL;
DOMAINfilter *DOMAINfilter::filter_reload = NULL;
volatile bool DOMAINfilter::reload_do = 0;
volatile int DOMAINfilter::_sync = 0;
volatile int DOMAINfilter::_sync_reload = 0;

/* SIP_HEADERfilter class */

// constructor
SIP_HEADERfilter::SIP_HEADERfilter() {
	count = 0;
	loadTime = 0;
	reload_do = false;
}

// destructor
SIP_HEADERfilter::~SIP_HEADERfilter() {
	for(map<string, header_data>::iterator iter = data.begin(); iter != data.end(); iter++) {
		iter->second.clean();
	}
}

void SIP_HEADERfilter::load(u_int32_t *global_flags, SqlDb *sqlDb) {
	this->loadFile(global_flags);
	if(opt_nocdr || is_sender() || is_client_packetbuffer_sender()) {
		return;
	}
	vector<db_row> vectDbRow;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool existsSensorsTable = sqlDb->existsTable("filter_sip_header_sensors");
	sqlDb->query(string("SELECT filter_sip_header.*") +
		     (existsSensorsTable ? 
		       ",(select group_concat(coalesce(sensor_id, -2)) \
  			  from filter_sip_header_sensors \
			  where filter_sip_header_id = filter_sip_header.id) as sensors_id" :
		       "") +
		     " FROM filter_sip_header");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		if(!(!existsSensorsTable || selectSensorsContainSensorId(row["sensors_id"]))) {
			continue;
		}
		count++;
		db_row* filterRow = new FILE_LINE(4009) db_row;
		filterRow->header = trim_str(row["header"]);
		filterRow->content = trim_str(row["content"]);
		filterRow->prefix = row["content_type"] == "prefix";
		filterRow->regexp = row["content_type"] == "regexp";
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	for (size_t i = 0; i < vectDbRow.size(); ++i) {
		item_data *item = new FILE_LINE(0) item_data;
		item->direction = 0;
		item->prefix = vectDbRow[i].prefix;
		item->regexp = vectDbRow[i].regexp;
		item->flags = this->getFlagsFromBaseData(&vectDbRow[i], global_flags);
		this->parseNatAliases(&vectDbRow[i], &item->nat_aliases);
		if(item->regexp) {
			data[vectDbRow[i].header].regexp[vectDbRow[i].content] = item;
		} else {
			data[vectDbRow[i].header].strict_prefix[vectDbRow[i].content] = item;
		}
		++count;
	}
	loadTime = getTimeMS();
	if(sverb.capture_filter) {
		syslog(LOG_NOTICE, "SIP_HEADERfilter::load");
	}
}

void SIP_HEADERfilter::loadFile(u_int32_t *global_flags) {
	extern char opt_capture_rules_sip_header_file[1024];
	if (is_sender() || is_client_packetbuffer_sender() || !opt_capture_rules_sip_header_file[0]) {
		return;
	}
	cCsv csv;
	csv.setFirstRowContainFieldNames();
	csv.load(opt_capture_rules_sip_header_file);
	unsigned rowsCount = csv.getRowsCount();
	vector<db_row> vectDbRow;
	for(unsigned i = 1; i <= rowsCount; i++) {
		map<string, string> row;
		csv.getRow(i, &row);
		count++;
		db_row *filterRow = new (db_row);
		filterRow->header = trim_str(row["header"]);
		filterRow->content = trim_str(row["content"]);
		filterRow->prefix = trim_str(row["content_type"]) == "prefix";
		filterRow->regexp = trim_str(row["content_type"]) == "regexp";
		this->loadBaseDataRow(&row, filterRow);
		vectDbRow.push_back(*filterRow);
		delete filterRow;
	}
	for(size_t i = 0; i < vectDbRow.size(); ++i) {
		item_data *item = new FILE_LINE(0) item_data;
		item->direction = 0;
		item->prefix = vectDbRow[i].prefix;
		item->regexp = vectDbRow[i].regexp;
		item->flags = this->getFlagsFromBaseData(&vectDbRow[i], global_flags);
		if(item->regexp) {
			data[vectDbRow[i].header].regexp[vectDbRow[i].content] = item;
		} else {
			data[vectDbRow[i].header].strict_prefix[vectDbRow[i].content] = item;
		}
		++count;
	}
}

int SIP_HEADERfilter::_add_call_flags(ParsePacket::ppContentsX *parseContents, volatile unsigned long int *flags, nat_aliases_t **nat_aliases, bool reconfigure) {
	
	if (this->count == 0) {
		// no filters, return 
		return 0;
	}
	
	for(map<string, header_data>::iterator it_header = this->data.begin(); it_header != this->data.end(); it_header++) {
		header_data *data = &it_header->second;
		string content = parseContents->getContentString((it_header->first + ":").c_str());
		if(content.empty()) {
			continue;
		}
		if(data->strict_prefix.size()) {
			map<string, item_data*>::iterator it_content = data->strict_prefix.lower_bound(content);
			if(it_content != data->strict_prefix.end() &&
			   it_content->first == content) {
				this->setCallFlagsFromFilterFlags(flags, it_content->second->flags, reconfigure);
				comb_nat_aliases(it_content->second->nat_aliases, nat_aliases);
				if(sverb.capture_filter) {
					syslog(LOG_NOTICE, "SIP_HEADERfilter::add_call_flags - strict (eq) : %s",  it_content->first.c_str());
				}
				return 1;
			}
			if(it_content != data->strict_prefix.begin()) {
				--it_content;
			}
			if(it_content->second->prefix &&
			   !strncmp(it_content->first.c_str(), content.c_str(), it_content->first.length())) {
				this->setCallFlagsFromFilterFlags(flags, it_content->second->flags, reconfigure);
				comb_nat_aliases(it_content->second->nat_aliases, nat_aliases);
				if(sverb.capture_filter) {
					syslog(LOG_NOTICE, "SIP_HEADERfilter::add_call_flags - prefix : %s",  it_content->first.c_str());
				}
				return 1;
			}
		}
		if(data->regexp.size()) {
			for(map<string, item_data*>::iterator it_content = data->regexp.begin(); it_content != data->regexp.end(); it_content++) {
				if(reg_match(content.c_str(), it_content->first.c_str(), __FILE__, __LINE__)) {
					this->setCallFlagsFromFilterFlags(flags, it_content->second->flags, reconfigure);
					comb_nat_aliases(it_content->second->nat_aliases, nat_aliases);
					if(sverb.capture_filter) {
						syslog(LOG_NOTICE, "SIP_HEADERfilter::add_call_flags - regexp : %s",  it_content->first.c_str());
					}
					return 1;
				}
			}
		}
	}
	
	return 0;
}

void SIP_HEADERfilter::dump2man(ostringstream &oss) {
	lock();
	for(map<string, header_data>::iterator it_header = filter_active->data.begin(); it_header != filter_active->data.end(); it_header++) {
		header_data *data = &it_header->second;
		for(map<string, item_data*>::iterator it_content = data->regexp.begin(); it_content != data->regexp.end(); it_content++) {
			oss << "Regex header[" << it_header->first << "] content[" << it_content->first << "] direction[" << it_content->second->direction << "] flags[0x" << hex << it_content->second->flags << "]" << endl;
		}
		for(map<string, item_data*>::iterator it_content = data->strict_prefix.begin(); it_content != data->strict_prefix.end(); it_content++) {
			oss << "Prefix header[" << it_header->first << "] content[" << it_content->first << "] direction[" << it_content->second->direction << "] flags[0x" << hex << it_content->second->flags << "]" << endl;
		}
	}
	unlock();
}

void SIP_HEADERfilter::_prepareCustomNodes(ParsePacket *parsePacket) {
	for(map<string, header_data>::iterator it_header = this->data.begin(); it_header != this->data.end(); it_header++) {
		parsePacket->prepareCustomNode((it_header->first + ":").c_str());
	}
}

int SIP_HEADERfilter::add_call_flags(ParsePacket::ppContentsX *parseContents, volatile unsigned long int *flags, nat_aliases_t **nat_aliases, bool reconfigure) {
	int rslt = 0;
	lock();
	if(filter_active) {
		rslt = filter_active->_add_call_flags(parseContents, flags, nat_aliases, reconfigure);
	}
	unlock();
	return(rslt);
}

void SIP_HEADERfilter::prepareCustomNodes(ParsePacket *parsePacket) {
	if(reload_do) {
		applyReload();
	}
	lock();
	if(filter_active) {
		filter_active->_prepareCustomNodes(parsePacket);
	}
	unlock();
}

void SIP_HEADERfilter::loadActive(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock();
	filter_active = new FILE_LINE(4010) SIP_HEADERfilter();
	filter_active->load(global_flags, sqlDb);
	unlock();
}

void SIP_HEADERfilter::freeActive() {
	lock();
	if(filter_active) {
		delete filter_active;
		filter_active = NULL;
	}
	unlock();
}

void SIP_HEADERfilter::prepareReload(u_int32_t *global_flags, SqlDb *sqlDb) {
	lock_reload();
	if(filter_reload) {
		delete filter_reload;
	}
	filter_reload = new FILE_LINE(4011) SIP_HEADERfilter;
	filter_reload->load(global_flags, sqlDb);
	reload_do = true;
	syslog(LOG_NOTICE, "SIP_HEADERfilter::prepareReload");
	unlock_reload();
}

void SIP_HEADERfilter::applyReload() {
	if(reload_do) {
		lock_reload();
		if(reload_do) {
			lock();
			delete filter_active;
			filter_active = filter_reload;
			unlock();
			filter_reload = NULL;
			reload_do = false; 
			syslog(LOG_NOTICE, "SIP_HEADERfilter::applyReload");
		}
		unlock_reload();
	}
}

SIP_HEADERfilter *SIP_HEADERfilter::filter_active = NULL;
SIP_HEADERfilter *SIP_HEADERfilter::filter_reload = NULL;
volatile bool SIP_HEADERfilter::reload_do = 0;
volatile unsigned long SIP_HEADERfilter::loadTime = 0;
volatile int SIP_HEADERfilter::_sync = 0;
volatile int SIP_HEADERfilter::_sync_reload = 0;



void cFilters::loadActive(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	global_flags = 0;
	IPfilter::loadActive(&global_flags, sqlDb);
	TELNUMfilter::loadActive(&global_flags, sqlDb);
	DOMAINfilter::loadActive(&global_flags, sqlDb);
	SIP_HEADERfilter::loadActive(&global_flags, sqlDb);
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cFilters::prepareReload(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	lock_reload();
	reload_global_flags = 0;
	IPfilter::prepareReload(&reload_global_flags, sqlDb);
	TELNUMfilter::prepareReload(&reload_global_flags, sqlDb);
	DOMAINfilter::prepareReload(&reload_global_flags, sqlDb);
	SIP_HEADERfilter::prepareReload(&reload_global_flags, sqlDb);
	reload_do = true;
	unlock_reload();
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cFilters::applyReload() {
	if(reload_do) {
		lock_reload();
		if(reload_do) {
			IPfilter::applyReload();
			TELNUMfilter::applyReload();
			DOMAINfilter::applyReload();
			SIP_HEADERfilter::applyReload();
			global_flags = reload_global_flags;
			reload_do = false;
		}
		unlock_reload();
	}
}

void cFilters::freeActive() {
	IPfilter::freeActive();
	TELNUMfilter::freeActive();
	DOMAINfilter::freeActive();
	SIP_HEADERfilter::freeActive();
}

u_int32_t cFilters::global_flags = 0;
u_int32_t cFilters::reload_global_flags = 0;
volatile bool cFilters::reload_do = 0;
volatile int cFilters::_sync_reload = 0;
