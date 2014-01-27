#include <syslog.h>
#include <string.h>
#include <math.h>
#include <vector>

#include "voipmonitor.h"
#include "config_mysql.h"
#include "calltable.h"
#include "odbc.h"
#include "sql_db.h"
#include "tools.h"

using namespace std;

void
config_load_mysql() {
	SqlDb *sqlDb = createSqlObject();
	SqlDb_row row;
	stringstream q;
	if(opt_id_sensor) {
		q << "SELECT * FROM sensor_conf WHERE id_sensor = " << opt_id_sensor << " LIMIT 1";
	} else {
		q << "SELECT * FROM sensor_conf LIMIT 1";
	}
	sqlDb->query(q.str());

	while((row = sqlDb->fetchRow())) {
		syslog(LOG_NOTICE, "Found configuration in database for id_sensor:[%d] - loading\n", opt_id_sensor);


//sipport
		vector<string>ports = split(row["sipport"].c_str(), split(",|;|\t|\r|\n", "|"), true);
		sipportmatrix[5060] = 0;
		for(size_t i = 0; i < ports.size(); i++) {
                        sipportmatrix[atoi(ports[i].c_str())] = 1;
                }


/*
		filterRow->ip = (unsigned int)strtoul(row["ip"].c_str(), NULL, 0);
		filterRow->mask = atoi(row["mask"].c_str());
		filterRow->direction = row.isNull("direction") ? 0 : atoi(row["direction"].c_str());
		filterRow->rtp = row.isNull("rtp") ? -1 : atoi(row["rtp"].c_str());
*/

	}
	delete sqlDb;
}
