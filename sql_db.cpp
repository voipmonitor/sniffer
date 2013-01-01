#include <stdio.h>
#include <iostream>
#include <syslog.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "sql_db.h"


extern int verbosity;
extern int opt_mysql_port;
extern char opt_match_header[128];
int sql_noerror = 0;


string SqlDb_row::operator [] (const char *fieldName) {
	int indexField = this->getIndexField(fieldName);
	if(indexField >= 0) {
		return(row[indexField].content);
	}
	return("");
}

string SqlDb_row::operator [] (string fieldName) {
	return((*this)[fieldName.c_str()]);
}

SqlDb_row::operator int() {
	return(!this->isEmpty());
}

void SqlDb_row::add(const char *content, string fieldName) {
	this->row.push_back(SqlDb_rowField(content, fieldName));
}

void SqlDb_row::add(string content, string fieldName) {
	this->row.push_back(SqlDb_rowField(content, fieldName));
}

void SqlDb_row::add(int content, string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%i", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(unsigned int content, string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%u", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(long int content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%li", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(double content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%lf", content);
		this->add(str_content, fieldName);
	}
}

int SqlDb_row::getIndexField(string fieldName) {
	for(size_t i = 0; i < row.size(); i++) {
		if(row[i].fieldName == fieldName) {
			return(i);
		}
	}
	if(this->sqlDb) {
		return(this->sqlDb->getIndexField(fieldName));
	}
	return(-1);
}

bool SqlDb_row::isEmpty() {
	return(!row.size());
}

bool SqlDb_row::isNull(string fieldName) {
	int indexField = this->getIndexField(fieldName);
	if(indexField >= 0) {
		return(row[indexField].null);
	}
	return(false);
}

string SqlDb_row::implodeFields(string separator, string border) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		rslt += border + '`' + this->row[i].fieldName + '`' + border;
	}
	return(rslt);
}

string SqlDb_row::implodeContent(string separator, string border) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		if(this->row[i].null) {
			rslt += "NULL";
		} else {
			rslt += border + this->row[i].content + border;
		}
	}
	return(rslt);
}

string SqlDb_row::keyvalList(string separator) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(this->row[i].null) {
			rslt += this->row[i].fieldName + ":NULL\n";
		} else {
			rslt += this->row[i].fieldName + separator + this->row[i].content + "\n";
		}
	}
	return(rslt);
}


SqlDb::SqlDb() {
	this->sysLog = false;
	this->clearLastError();
	this->maxQueryPass = UINT_MAX;
}

SqlDb::~SqlDb() {
	//cout << "destruct SqlDb" << endl;
}

void SqlDb::setConnectParameters(string server, string user, string password, string database) {
	this->conn_server = server;
	this->conn_user = user;
	this->conn_password = password;
	this->conn_database = database;
}

void SqlDb::enableSysLog() {
	this->sysLog = true;
}

bool SqlDb::reconnect() {
	this->disconnect();
	return(this->connect());
}

int SqlDb::insert(string table, SqlDb_row row, string contentBorder) {
	string query = "INSERT INTO " + table + " ( " + row.implodeFields() + " ) VALUES ( " + row.implodeContent(",", "") + " )";
	if(this->query(query)) {
		return(this->getInsertId());
	}
	return(-1);
}

int SqlDb::getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row, string contentBorder) {
	string query = "SELECT * FROM " + table + " WHERE " + uniqueField + " = " + 
		       contentBorder + row[uniqueField] + contentBorder;
	if(this->query(query)) {
		SqlDb_row rsltRow = this->fetchRow();
		if(rsltRow) {
			return(atoi(rsltRow[idField].c_str()));
		}
	}
	return(this->insert(table, row, contentBorder));
}

void SqlDb::setLastErrorString(string lastErrorString, bool sysLog) {
	this->lastErrorString = lastErrorString;
	if(sysLog && lastErrorString != "" && this->sysLog) {
		syslog(LOG_ERR, "%s", lastErrorString.c_str());
	}
}


SqlDb_mysql::SqlDb_mysql() {
	this->hMysql = NULL;
	this->hMysqlConn = NULL;
	this->hMysqlRes = NULL;
}

SqlDb_mysql::~SqlDb_mysql() {
	//cout << "destruct SqlDb_mysql" << endl;
	this->clean();
}

bool SqlDb_mysql::connect() {
	this->hMysql = mysql_init(NULL);
	if(this->hMysql) {
		this->hMysqlConn = mysql_real_connect(
					this->hMysql,
					this->conn_server.c_str(), this->conn_user.c_str(), this->conn_password.c_str(), this->conn_database.c_str(),
					opt_mysql_port, NULL, 0);
		if(this->hMysqlConn) {
			return(true);
		} else {
			this->checkLastError("connect error", true);
		}
	} else {
		this->setLastErrorString("mysql_init failed - insufficient memory ?", true);
	}
	return(false);
}

void SqlDb_mysql::disconnect() {
	if(this->hMysqlRes) {
		mysql_free_result(this->hMysqlRes);
		this->hMysqlRes = NULL;
	}
	if(this->hMysqlConn) {
		mysql_close(this->hMysqlConn);
		this->hMysqlConn = NULL;
		this->hMysql = NULL;
	} else if(this->hMysql) {
		mysql_close(this->hMysql);
		this->hMysql = NULL;
	}
}

bool SqlDb_mysql::connected() {
	return(this->hMysqlConn != NULL);
}

bool SqlDb_mysql::query(string query) {
	if(verbosity > 0) { 
		cout << query << endl;
	}
	bool rslt = false;
	if(this->hMysqlRes) {
		mysql_free_result(this->hMysqlRes);
		this->hMysqlRes = NULL;
	}
	for(unsigned int pass = 0; pass < this->maxQueryPass && !rslt; pass++) {
		if(pass > 0) {
			sleep(1);
		}
		if(!this->connected()) {
			this->connect();
		}
		if(this->connected()) {
			if(mysql_query(this->hMysqlConn, query.c_str())) {
				if(!sql_noerror)
					this->checkLastError("query error in [" + query + "]", true);
				if(this->getLastError() == 2006) { // MySQL server has gone away
					if(pass < this->maxQueryPass - 1) {
						this->reconnect();
					}
				} else {
					break;
				}
			} else {
				rslt = true;
			}
		}
	}
	return(rslt);
}

SqlDb_row SqlDb_mysql::fetchRow() {
	SqlDb_row row(this);
	if(this->hMysqlConn) {
		if(!this->hMysqlRes) {
			this->hMysqlRes = mysql_use_result(this->hMysqlConn);
			if(this->hMysqlRes) {
				this->fields.clear();
				MYSQL_FIELD *field;
				for(int i = 0; (field = mysql_fetch_field(this->hMysqlRes)); i++) {
					this->fields.push_back(field->name);
				}
			} else {
				this->checkLastError("fetch row error in function mysql_use_result", true);
			}
		}
		if(this->hMysqlRes) {
			MYSQL_ROW mysqlRow = mysql_fetch_row(hMysqlRes);
			if(mysqlRow) {
				unsigned int numFields = mysql_num_fields(this->hMysqlRes);
				for(unsigned int i = 0; i < numFields; i++) {
					row.add(mysqlRow[i]);
				}
			} else {
				this->checkLastError("fetch row error", true);
			}
		}
	}
	return(row);
}

int SqlDb_mysql::getInsertId() {
	if(this->hMysqlConn) {
		return(mysql_insert_id(this->hMysqlConn));
	}
	return(-1);
}

int SqlDb_mysql::getIndexField(string fieldName) {
	for(size_t i = 0; i < this->fields.size(); i++) {
		if(this->fields[i] == fieldName) {
			return(i);
		}
	}
	return(-1);
}

string SqlDb_mysql::escape(const char *inputString) {
	if(inputString && inputString[0]) {
		int length = strlen(inputString);
		int sizeBuffer = length * 2 + 10;
		char *buffer = new char[sizeBuffer];
		mysql_real_escape_string(this->hMysqlConn, buffer, inputString, length);
		string rslt = buffer;
		delete [] buffer;
		return(rslt);
	} else {
		return("");
	}
}

bool SqlDb_mysql::checkLastError(string prefixError, bool sysLog, bool clearLastError) {
	if(this->hMysql) {
		unsigned int errno = mysql_errno(this->hMysql);
		if(errno) {
			this->setLastError(errno, (prefixError + ":  " + mysql_error(this->hMysql)).c_str(), sysLog);
			return(true);
		} else if(clearLastError) {
			this->clearLastError();
		}
	}
	return(false);
}

void SqlDb_mysql::clean() {
	this->disconnect();
	this->fields.clear();
}

void SqlDb_mysql::createSchema() {
	string query = "CREATE TABLE IF NOT EXISTS `filter_ip` (\
  `id` int(32) NOT NULL AUTO_INCREMENT,\
  `ip` int(32) unsigned DEFAULT NULL,\
  `mask` int(8) DEFAULT NULL,\
  `direction` tinyint(8) DEFAULT '0',\
  `rtp` tinyint(1) DEFAULT '0',\
  `sip` tinyint(1) DEFAULT '0',\
  `register` tinyint(1) DEFAULT '0',\
  `graph` tinyint(1) DEFAULT '0',\
  `wav` tinyint(1) DEFAULT '0',\
  `note` text,\
  PRIMARY KEY (`id`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";
	
	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `filter_telnum` (\
  `id` int(32) NOT NULL AUTO_INCREMENT,\
  `prefix` bigint(32) unsigned DEFAULT NULL,\
  `fixed_len` int(32) unsigned DEFAULT '0',\
  `direction` tinyint(8) DEFAULT '0',\
  `rtp` tinyint(1) DEFAULT '0',\
  `sip` tinyint(1) DEFAULT '0',\
  `register` tinyint(1) DEFAULT '0',\
  `graph` tinyint(1) DEFAULT '0',\
  `wav` tinyint(1) DEFAULT '0',\
  `note` text,\
  PRIMARY KEY (`id`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr_sip_response` (\
  `id` smallint(5) unsigned NOT NULL AUTO_INCREMENT,\
  `lastSIPresponse` varchar(255) DEFAULT NULL,\
  PRIMARY KEY (`id`),\
  UNIQUE KEY `lastSIPresponse` (`lastSIPresponse`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr_ua` (\
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,\
  `ua` varchar(512) DEFAULT NULL,\
  PRIMARY KEY (`id`),\
  UNIQUE KEY `ua` (`ua`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `calldate` datetime NOT NULL,\
  `callend` datetime NOT NULL,\
  `duration` mediumint(8) unsigned DEFAULT NULL,\
  `connect_duration` mediumint(8) unsigned DEFAULT NULL,\
  `progress_time` mediumint(8) unsigned DEFAULT NULL,\
  `first_rtp_time` mediumint(8) unsigned DEFAULT NULL,\
  `caller` varchar(255) DEFAULT NULL,\
  `caller_domain` varchar(255) DEFAULT NULL,\
  `caller_reverse` varchar(255) DEFAULT NULL,\
  `callername` varchar(255) DEFAULT NULL,\
  `callername_reverse` varchar(255) DEFAULT NULL,\
  `called` varchar(255) DEFAULT NULL,\
  `called_domain` varchar(255) DEFAULT NULL,\
  `called_reverse` varchar(255) DEFAULT NULL,\
  `sipcallerip` int(10) unsigned DEFAULT NULL,\
  `sipcalledip` int(10) unsigned DEFAULT NULL,\
  `whohanged` enum('caller','callee') DEFAULT NULL,\
  `bye` tinyint(3) unsigned DEFAULT NULL,\
  `lastSIPresponse_id` smallint(5) unsigned DEFAULT NULL,\
  `lastSIPresponseNum` smallint(5) unsigned DEFAULT NULL,\
  `sighup` tinyint(4) DEFAULT NULL,\
  `a_index` tinyint(4) DEFAULT NULL,\
  `b_index` tinyint(4) DEFAULT NULL,\
  `a_payload` int(11) DEFAULT NULL,\
  `b_payload` int(11) DEFAULT NULL,\
  `a_saddr` int(10) unsigned DEFAULT NULL,\
  `b_saddr` int(10) unsigned DEFAULT NULL,\
  `a_received` mediumint(8) unsigned DEFAULT NULL,\
  `b_received` mediumint(8) unsigned DEFAULT NULL,\
  `a_lost` mediumint(8) unsigned DEFAULT NULL,\
  `b_lost` mediumint(8) unsigned DEFAULT NULL,\
  `a_ua_id` int(10) unsigned DEFAULT NULL,\
  `b_ua_id` int(10) unsigned DEFAULT NULL,\
  `a_avgjitter_mult10` mediumint(8) unsigned DEFAULT NULL,\
  `b_avgjitter_mult10` mediumint(8) unsigned DEFAULT NULL,\
  `a_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `b_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `a_sl1` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl2` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl3` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl4` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl5` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl6` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl7` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl8` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl9` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl10` mediumint(8) unsigned DEFAULT NULL,\
  `a_d50` mediumint(8) unsigned DEFAULT NULL,\
  `a_d70` mediumint(8) unsigned DEFAULT NULL,\
  `a_d90` mediumint(8) unsigned DEFAULT NULL,\
  `a_d120` mediumint(8) unsigned DEFAULT NULL,\
  `a_d150` mediumint(8) unsigned DEFAULT NULL,\
  `a_d200` mediumint(8) unsigned DEFAULT NULL,\
  `a_d300` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl1` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl2` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl3` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl4` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl5` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl6` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl7` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl8` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl9` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl10` mediumint(8) unsigned DEFAULT NULL,\
  `b_d50` mediumint(8) unsigned DEFAULT NULL,\
  `b_d70` mediumint(8) unsigned DEFAULT NULL,\
  `b_d90` mediumint(8) unsigned DEFAULT NULL,\
  `b_d120` mediumint(8) unsigned DEFAULT NULL,\
  `b_d150` mediumint(8) unsigned DEFAULT NULL,\
  `b_d200` mediumint(8) unsigned DEFAULT NULL,\
  `b_d300` mediumint(8) unsigned DEFAULT NULL,\
  `a_mos_f1_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_mos_f2_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_mos_adapt_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_f1_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_f2_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_adapt_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_rtcp_loss` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_maxfr` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_avgfr_mult10` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_avgjitter_mult10` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_loss` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_maxfr` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_avgfr_mult10` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_avgjitter_mult10` smallint(5) unsigned DEFAULT NULL,\
  `payload` int(11) DEFAULT NULL,\
  `jitter_mult10` mediumint(8) unsigned DEFAULT NULL,\
  `mos_min_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_mos_min_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_min_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `packet_loss_perc_mult1000` mediumint(8) unsigned DEFAULT NULL,\
  `a_packet_loss_perc_mult1000` mediumint(8) unsigned DEFAULT NULL,\
  `b_packet_loss_perc_mult1000` mediumint(8) unsigned DEFAULT NULL,\
  `delay_sum` mediumint(8) unsigned DEFAULT NULL,\
  `a_delay_sum` mediumint(8) unsigned DEFAULT NULL,\
  `b_delay_sum` mediumint(8) unsigned DEFAULT NULL,\
  `delay_avg_mult100` mediumint(8) unsigned DEFAULT NULL,\
  `a_delay_avg_mult100` mediumint(8) unsigned DEFAULT NULL,\
  `b_delay_avg_mult100` mediumint(8) unsigned DEFAULT NULL,\
  `delay_cnt` mediumint(8) unsigned DEFAULT NULL,\
  `a_delay_cnt` mediumint(8) unsigned DEFAULT NULL,\
  `b_delay_cnt` mediumint(8) unsigned DEFAULT NULL,\
  `rtcp_avgfr_mult10` smallint(5) unsigned DEFAULT NULL,\
  `rtcp_avgjitter_mult10` smallint(5) unsigned DEFAULT NULL,\
  `lost` mediumint(8) unsigned DEFAULT NULL,\
  `id_sensor` smallint(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `calldate` (`calldate`),\
  KEY `callend` (`callend`),\
  KEY `duration` (`duration`),\
  KEY `source` (`caller`),\
  KEY `source_reverse` (`caller_reverse`),\
  KEY `destination` (`called`),\
  KEY `destination_reverse` (`called_reverse`),\
  KEY `callername` (`callername`),\
  KEY `callername_reverse` (`callername_reverse`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`),\
  KEY `lastSIPresponseNum` (`lastSIPresponseNum`),\
  KEY `bye` (`bye`),\
  KEY `a_saddr` (`a_saddr`),\
  KEY `b_saddr` (`b_saddr`),\
  KEY `a_lost` (`a_lost`),\
  KEY `b_lost` (`b_lost`),\
  KEY `a_maxjitter` (`a_maxjitter`),\
  KEY `b_maxjitter` (`b_maxjitter`),\
  KEY `a_rtcp_loss` (`a_rtcp_loss`),\
  KEY `a_rtcp_maxfr` (`a_rtcp_maxfr`),\
  KEY `a_rtcp_maxjitter` (`a_rtcp_maxjitter`),\
  KEY `b_rtcp_loss` (`b_rtcp_loss`),\
  KEY `b_rtcp_maxfr` (`b_rtcp_maxfr`),\
  KEY `b_rtcp_maxjitter` (`b_rtcp_maxjitter`),\
  KEY `a_ua_id` (`a_ua_id`),\
  KEY `b_ua_id` (`b_ua_id`),\
  KEY `a_avgjitter_mult10` (`a_avgjitter_mult10`),\
  KEY `b_avgjitter_mult10` (`b_avgjitter_mult10`),\
  KEY `a_rtcp_avgjitter_mult10` (`a_rtcp_avgjitter_mult10`),\
  KEY `b_rtcp_avgjitter_mult10` (`b_rtcp_avgjitter_mult10`),\
  KEY `lastSIPresponse_id` (`lastSIPresponse_id`),\
  KEY `payload` (`payload`),\
  KEY `id_sensor` (`id_sensor`),\
  CONSTRAINT `cdr_ibfk_1` FOREIGN KEY (`lastSIPresponse_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `cdr_ibfk_2` FOREIGN KEY (`a_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `cdr_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `message` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `calldate` datetime NOT NULL,\
  `caller` varchar(255) DEFAULT NULL,\
  `caller_domain` varchar(255) DEFAULT NULL,\
  `caller_reverse` varchar(255) DEFAULT NULL,\
  `callername` varchar(255) DEFAULT NULL,\
  `callername_reverse` varchar(255) DEFAULT NULL,\
  `called` varchar(255) DEFAULT NULL,\
  `called_domain` varchar(255) DEFAULT NULL,\
  `called_reverse` varchar(255) DEFAULT NULL,\
  `sipcallerip` int(10) unsigned DEFAULT NULL,\
  `sipcalledip` int(10) unsigned DEFAULT NULL,\
  `bye` tinyint(3) unsigned DEFAULT NULL,\
  `lastSIPresponse_id` smallint(5) unsigned DEFAULT NULL,\
  `lastSIPresponseNum` smallint(5) unsigned DEFAULT NULL,\
  `id_sensor` smallint(10) unsigned DEFAULT NULL,\
  `a_ua_id` int(10) unsigned DEFAULT NULL,\
  `b_ua_id` int(10) unsigned DEFAULT NULL,\
  `fbasename` varchar(255) DEFAULT NULL,\
  `message` TEXT,\
  PRIMARY KEY (`ID`),\
  KEY `calldate` (`calldate`),\
  KEY `source` (`caller`),\
  KEY `source_reverse` (`caller_reverse`),\
  KEY `destination` (`called`),\
  KEY `destination_reverse` (`called_reverse`),\
  KEY `callername` (`callername`),\
  KEY `callername_reverse` (`callername_reverse`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`),\
  KEY `lastSIPresponseNum` (`lastSIPresponseNum`),\
  KEY `bye` (`bye`),\
  KEY `lastSIPresponse_id` (`lastSIPresponse_id`),\
  KEY `id_sensor` (`id_sensor`),\
  KEY `a_ua_id` (`a_ua_id`),\
  KEY `b_ua_id` (`b_ua_id`),\
  KEY `fbasename` (`fbasename`),\
  CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`lastSIPresponse_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`a_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `messages_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr_next` (\
  `cdr_ID` int(10) unsigned NOT NULL,\
  `custom_header1` varchar(255) DEFAULT NULL,\
  `fbasename` varchar(255) DEFAULT NULL,\
  PRIMARY KEY (`cdr_ID`),\
  KEY `fbasename` (`fbasename`),\
  CONSTRAINT `cdr_next_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `register` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `calldate` datetime NOT NULL,\
  `sipcallerip` int(32) unsigned NOT NULL,\
  `sipcalledip` int(32) unsigned NOT NULL,\
  `from_num` varchar(255) NULL DEFAULT NULL,\
  `from_name` varchar(255) NULL DEFAULT NULL,\
  `from_domain` varchar(255) NULL DEFAULT NULL,\
  `to_num` varchar(255) NULL DEFAULT NULL,\
  `to_domain` varchar(255) NULL DEFAULT NULL,\
  `contact_num` varchar(255) NULL DEFAULT NULL,\
  `contact_domain` varchar(255) NULL DEFAULT NULL,\
  `digestusername` varchar(255) NULL DEFAULT NULL,\
  `digestrealm` varchar(255) NULL DEFAULT NULL,\
  `expires`     mediumint NULL DEFAULT NULL,\
  `expires_at`  datetime NULL DEFAULT NULL,\
  `state`  tinyint unsigned NULL DEFAULT NULL,\
  `ua_id` int(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `calldate` (`calldate`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`),\
  KEY `from_num` (`from_num`),\
  KEY `digestusername` (`digestusername`)\
) ENGINE=MEMORY DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `register_state` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `created_at` datetime NOT NULL,\
  `sipcallerip` int(32) unsigned NOT NULL,\
  `sipcalledip` int(32) unsigned NOT NULL,\
  `from_num` varchar(255) NULL DEFAULT NULL,\
  `to_num` varchar(255) NULL DEFAULT NULL,\
  `contact_num` varchar(255) NULL DEFAULT NULL,\
  `contact_domain` varchar(255) NULL DEFAULT NULL,\
  `digestusername` varchar(255) NULL DEFAULT NULL,\
  `expires` mediumint NULL DEFAULT NULL,\
  `state` tinyint unsigned NULL DEFAULT NULL,\
  `ua_id` int(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `created_at` (`created_at`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `register_failed` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `counter` int DEFAULT 0,\
  `created_at` datetime NOT NULL,\
  `sipcallerip` int(32) unsigned NOT NULL,\
  `sipcalledip` int(32) unsigned NOT NULL,\
  `from_num` varchar(255) NULL DEFAULT NULL,\
  `to_num` varchar(255) NULL DEFAULT NULL,\
  `contact_num` varchar(255) NULL DEFAULT NULL,\
  `contact_domain` varchar(255) NULL DEFAULT NULL,\
  `digestusername` varchar(255) NULL DEFAULT NULL,\
  `ua_id` int(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `created_at` (`created_at`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `sensors` (\
  `id_sensor` int(32) unsigned NOT NULL,\
  `host` varchar(255) NULL DEFAULT NULL,\
  `port` int(8) NULL DEFAULT NULL,\
  PRIMARY KEY (`id_sensor`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `ipacc_ipall` (\
  `saddr` int(32) unsigned NOT NULL,\
  `daddr` int(32) unsigned NOT NULL,\
  `proto` smallint(4) unsigned NOT NULL,\
  `octects` mediumint(32) unsigned NOT NULL,\
  `interval` varchar(255) NULL DEFAULT NULL,\
  KEY `saddr` (`saddr`),\
  KEY `daddr` (`daddr`),\
  KEY `interval` (`interval`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	//5.2 -> 5.3
	sql_noerror = 1;
	if(opt_match_header[0] != '\0') {
		query = "ALTER TABLE cdr_next ADD match_header VARCHAR(128), ADD KEY `match_header` (`match_header`);";
		this->query(query);
	}
	//5.3 -> 5.4
	query = "ALTER TABLE register ADD KEY `to_domain` (`to_domain`), ADD KEY `to_num` (`to_num`);";
	this->query(query);
	query = "ALTER TABLE register_state ADD `to_domain` varchar(255) NULL DEFAULT NULL;";
	this->query(query);
	query = "ALTER TABLE register_failed ADD `to_domain` varchar(255) NULL DEFAULT NULL;";
	this->query(query);

	//5.4 -> 5.5
	query = "ALTER TABLE register_state ADD `sipcalledip` int(32) unsigned, ADD KEY `sipcalledip` (`sipcalledip`);";
	this->query(query);
	query = "ALTER TABLE register_failed ADD `sipcalledip` int(32) unsigned, ADD KEY `sipcalledip` (`sipcalledip`);";
	this->query(query);

	sql_noerror = 0;
}

