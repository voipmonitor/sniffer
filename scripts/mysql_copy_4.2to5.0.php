<?

error_reporting(0);

define("HOST", "localhost");
define("USER", "root");
define("PASS", "");

define("SOURCE_DB", "voipmonitor");
define("DEST_DB", "voipmonitor5");

function varchar_reverse($value, $table, $newname, $reverse = true) {
	$value = mysql_escape_string($value);
	$query = "SELECT id, `$newname` FROM `$table` WHERE `$newname` = '$value'";
	$res2 = mysql_query($query);
	if (!$res2) {
#		echo $query."\n";
		die('Invalid query '.($query).': ' . mysql_error());
	}
	if(mysql_num_rows($res2) > 0) {
		$row2 = mysql_fetch_array($res2);
		return($row2['id']);
	} else {
		if($reverse) {
			$query = "INSERT INTO `$table` SET `$newname` = '$value', `$newname"."_reverse` = reverse('$value')";
		} else {
			$query = "INSERT INTO `$table` SET `$newname` = '$value'";
		}
		#echo $query."\n";
		$res2 = mysql_query($query);
		if (!$res2) {
	#		echo $query."\n";
			die('Invalid query '.($query).': ' . mysql_error());
		}
		return(mysql_insert_id());
	}
}

$cmd = "mysqldump ".SOURCE_DB." -u".USER." $pass --ignore-table=".SOURCE_DB.".cdr | mysql ".DEST_DB." -u".USER." $pass";
echo $cmd."\n";
system($cmd);

mysql_connect(HOST, USER, PASS);
mysql_select_db(DEST_DB);
#mysql_query("SET autocommit=0;");
mysql_query("SET unique_checks=0;");
mysql_query("SET foreign_key_checks=0;");

$a = 0;
$b = 1000;
#$cur = 13063293;
$query = "SELECT ID FROM ".SOURCE_DB.".cdr ORDER BY ID DESC LIMIT 1";
echo $query."\n";
$res = mysql_query($query);
$row = mysql_fetch_assoc($res);
$max = $row['ID'];
$cur = 0;
while($cur <= $max){

	$query = "SELECT * FROM ".SOURCE_DB.".cdr WHERE ID > $cur AND ID <= ".($cur + 1000);
	$cur += 1000;
	echo $query."\n";
	$a += 1000;
	$res = mysql_query($query);

	$i = 0;
	while($row = mysql_fetch_array($res)) {
		$query = "INSERT INTO cdr SET 
		ID = '".$row['ID']."',
		calldate = '".$row['calldate']."',
		callend = DATE_ADD('".$row['calldate']."', INTERVAL ".$row['duration']." SECOND),
		duration = '".$row['duration']."',
		connect_duration = '".$row['connect_duration']."',
		progress_time = '".$row['progress_time']."',
		first_rtp_time = '".$row['first_rtp_time']."',
		caller = '".$row['caller']."',
		caller_domain = '".$row['caller_domain']."',
		caller_reverse = '".$row['caller_reverse']."',
		callername = '".$row['callername']."',
		callername_reverse = '".$row['callername_reverse']."',
		called = '".$row['called']."',
		called_domain = '".$row['called_domain']."',
		called_reverse = '".$row['called_reverse']."',
		sipcallerip = '".$row['sipcallerip']."',
		sipcalledip = '".$row['sipcalledip']."',
		whohanged = '".$row['whohanged']."',
		bye = '".$row['bye']."',
		lastSIPresponse_id = '".varchar_reverse($row['lastSIPresponse'], 'cdr_sip_response', 'lastSIPresponse', 0)."',
		lastSIPresponseNum = '".$row['lastSIPresponseNum']."',
		sighup = '".$row['sighup']."',
		a_index = '".$row['a_index']."',
		b_index = '".$row['b_index']."',
		a_payload = '".$row['a_payload']."',
		b_payload = '".$row['b_payload']."',
		a_saddr = '".$row['a_saddr']."',
		b_saddr = '".$row['b_saddr']."',
		`a_received` = '".$row['a_received']."',
		`b_received` = '".$row['b_received']."',
		`a_lost` = '".$row['a_lost']."',
		`b_lost` = '".$row['b_lost']."',
		a_ua_id = ".varchar_reverse($row['a_ua'], 'cdr_ua', 'ua', 0).",
		b_ua_id = ".varchar_reverse($row['b_ua'], 'cdr_ua', 'ua', 0).",
		a_avgjitter_mult10 = '".($row['a_avgjitter'] * 10)."',
		b_avgjitter_mult10 = '".($row['b_avgjitter'] * 10)."',
		`a_maxjitter` = '".$row['a_maxjitter']."',
		`b_maxjitter` = '".$row['b_maxjitter']."',
		`a_sl1` = '".$row['a_sl1']."',
		`a_sl2` = '".$row['a_sl2']."',
		`a_sl3` = '".$row['a_sl3']."',
		`a_sl4` = '".$row['a_sl4']."',
		`a_sl5` = '".$row['a_sl5']."',
		`a_sl6` = '".$row['a_sl6']."',
		`a_sl7` = '".$row['a_sl7']."',
		`a_sl8` = '".$row['a_sl8']."',
		`a_sl9` = '".$row['a_sl9']."',
		`a_sl10` = '".$row['a_sl10']."',
		`a_d50` = '".$row['a_d50']."',
		`a_d70` = '".$row['a_d70']."',
		`a_d90` = '".$row['a_d90']."',
		`a_d120` = '".$row['a_d120']."',
		`a_d150` = '".$row['a_d150']."',
		`a_d200` = '".$row['a_d200']."',
		`a_d300` = '".$row['a_d300']."',
		`b_sl1` = '".$row['b_sl1']."',
		`b_sl2` = '".$row['b_sl2']."',
		`b_sl3` = '".$row['b_sl3']."',
		`b_sl4` = '".$row['b_sl4']."',
		`b_sl5` = '".$row['b_sl5']."',
		`b_sl6` = '".$row['b_sl6']."',
		`b_sl7` = '".$row['b_sl7']."',
		`b_sl8` = '".$row['b_sl8']."',
		`b_sl9` = '".$row['b_sl9']."',
		`b_sl10` = '".$row['b_sl9']."',
		`b_d50` = '".$row['b_d50']."',
		`b_d70` = '".$row['b_d70']."',
		`b_d90` = '".$row['b_d90']."',
		`b_d120` = '".$row['b_d120']."',
		`b_d150` = '".$row['b_d150']."',
		`b_d200` = '".$row['b_d200']."',
		`b_d300` = '".$row['b_d300']."',
		`a_mos_f1_mult10` = '".($row['a_mos_f1'] * 10)."',
		`a_mos_f2_mult10` = '".($row['a_mos_f2'] * 10)."',
		`a_mos_adapt_mult10` = '".($row['a_mos_adapt'] * 10)."',
		`b_mos_f1_mult10` = '".($row['b_mos_f1'] * 10)."',
		`b_mos_f2_mult10` = '".($row['b_mos_f2'] * 10)."',
		`b_mos_adapt_mult10` = '".($row['b_mos_adapt'] * 10)."',
		`a_rtcp_loss` = '".$row['a_rtcp_loss']."',
		`a_rtcp_maxfr` = '".$row['a_rtcp_maxfr']."',
		`a_rtcp_avgfr_mult10` = '".($row['a_rtcp_avgfr_mult10'] * 10)."',
		`b_rtcp_loss` = '".$row['b_rtcp_loss']."',
		`b_rtcp_maxfr` = '".$row['b_rtcp_maxfr']."',
		`b_rtcp_avgfr_mult10` = '".($row['b_rtcp_avgfr_mult10'] * 10)."',
		`payload` =
			if('".$row['a_received']."' > 0 OR '".$row['b_received']."' > 0,
			   if('".$row['a_received']."' > 0, '".$row['a_payload']."', '".$row['b_payload']."'),
			   NULL),

		`jitter_mult10` =
			GREATEST('".$row['a_avgjitter']."', '".$row['b_avgjitter']."') * 10,
		`mos_min_mult10` =
			if('".$row['a_mos_f1']."' > 0 OR '".$row['a_mos_f2']."' > 0 OR '".$row['a_mos_adapt']."' > 0 OR
			   '".$row['b_mos_f1']."' > 0 OR '".$row['b_mos_f2']."' > 0 OR '".$row['b_mos_adapt']."' > 0,
			   LEAST(if('".$row['a_mos_f1']."' > 0, '".$row['a_mos_f1']."', 10),
			   LEAST(if('".$row['a_mos_f2']."' > 0, '".$row['a_mos_f2']."', 10),
			   LEAST(if('".$row['a_mos_adapt']."' > 0, '".$row['a_mos_adapt']."', 10),
			   LEAST(if('".$row['b_mos_f1']."' > 0, '".$row['b_mos_f1']."', 10),
			   LEAST(if('".$row['b_mos_f2']."' > 0, '".$row['b_mos_f2']."', 10),
				 if('".$row['b_mos_adapt']."' > 0, '".$row['b_mos_adapt']."', 10)))))) * 10,
			   0),
		`a_mos_min_mult10` =
			if('".$row['a_mos_f1']."' > 0 OR '".$row['a_mos_f2']."' > 0 OR '".$row['a_mos_adapt']."' > 0,
			   LEAST(if('".$row['a_mos_f1']."' > 0, '".$row['a_mos_f1']."', 10),
			   LEAST(if('".$row['a_mos_f2']."' > 0, '".$row['a_mos_f2']."', 10),
				 if('".$row['a_mos_adapt']."' > 0, '".$row['a_mos_adapt']."', 10))) * 10,
			   0),
		`b_mos_min_mult10` =
			if('".$row['b_mos_f1']."' > 0 OR '".$row['b_mos_f2']."' > 0 OR '".$row['b_mos_adapt']."' > 0,
			   LEAST(if('".$row['b_mos_f1']."' > 0, '".$row['b_mos_f1']."', 10),
			   LEAST(if('".$row['b_mos_f2']."' > 0, '".$row['b_mos_f2']."', 10),
				 if('".$row['b_mos_adapt']."' > 0, '".$row['b_mos_adapt']."', 10))) * 10,
			   0),
		`packet_loss_perc_mult1000` =
			GREATEST(if((coalesce('".$row['a_received']."', 0) + coalesce('".$row['a_lost']."', 0)) > 0,
				     (coalesce('".$row['a_lost']."', 0) / (coalesce('".$row['a_received']."', 0) + coalesce('".$row['a_lost']."', 0))) * 100,
				     0),
				 if((coalesce('".$row['b_received']."', 0) + coalesce('".$row['b_lost']."', 0)) > 0,
				     (coalesce('".$row['b_lost']."', 0) / (coalesce('".$row['b_received']."', 0) + coalesce('".$row['b_lost']."', 0))) * 100,
				     0)) * 1000,
		`a_packet_loss_perc_mult1000` =
			if((coalesce('".$row['a_received']."', 0) + coalesce('".$row['a_lost']."', 0)) > 0,
			   (coalesce('".$row['a_lost']."', 0) / (coalesce('".$row['a_received']."', 0) + coalesce('".$row['a_lost']."', 0))) * 100,
			   0) * 1000,
		`b_packet_loss_perc_mult1000` =
			if((coalesce('".$row['b_received']."', 0) + coalesce('".$row['b_lost']."', 0)) > 0,
			   (coalesce('".$row['b_lost']."', 0) / (coalesce('".$row['b_received']."', 0) + coalesce('".$row['b_lost']."', 0))) * 100,
			   0) * 1000,
		`delay_sum` =
			GREATEST(coalesce('".$row['a_d50']."', 0) * 60 + coalesce('".$row['a_d70']."', 0) * 80 + coalesce('".$row['a_d90']."', 0) * 105 + coalesce('".$row['a_d120']."', 0) * 135 +
					coalesce('".$row['a_d150']."', 0) * 175 + coalesce('".$row['a_d200']."', 0) * 250 + coalesce('".$row['a_d300']."', 0) * 300,
				 coalesce('".$row['b_d50']."', 0) * 60 + coalesce('".$row['b_d70']."', 0) * 80 + coalesce('".$row['b_d90']."', 0) * 105 + coalesce('".$row['b_d120']."', 0) * 135 +
					coalesce('".$row['b_d150']."', 0) * 175 + coalesce('".$row['b_d200']."', 0) * 250 + coalesce('".$row['b_d300']."', 0) * 300),
		`a_delay_sum` =
			coalesce('".$row['a_d50']."', 0) * 60 + coalesce('".$row['a_d70']."', 0) * 80 + coalesce('".$row['a_d90']."', 0) * 105 + coalesce('".$row['a_d120']."', 0) * 135 +
				coalesce('".$row['a_d150']."', 0) * 175 + coalesce('".$row['a_d200']."', 0) * 250 + coalesce('".$row['a_d300']."', 0) * 300,
		`b_delay_sum` =
			coalesce('".$row['b_d50']."', 0) * 60 + coalesce('".$row['b_d70']."', 0) * 80 + coalesce('".$row['b_d90']."', 0) * 105 + coalesce('".$row['b_d120']."', 0) * 135 +
				coalesce('".$row['b_d150']."', 0) * 175 + coalesce('".$row['b_d200']."', 0) * 250 + coalesce('".$row['b_d300']."', 0) * 300,
		`delay_avg_mult100` =
			GREATEST(if((coalesce('".$row['a_d50']."', 0) + coalesce('".$row['a_d70']."', 0) + coalesce('".$row['a_d90']."', 0) + coalesce('".$row['a_d120']."', 0) +
					coalesce('".$row['a_d150']."', 0) + coalesce('".$row['a_d200']."', 0) + coalesce('".$row['a_d300']."', 0)) > 0,
				    ((coalesce('".$row['a_d50']."', 0) * 60 + coalesce('".$row['a_d70']."', 0) * 80 + coalesce('".$row['a_d90']."', 0) * 105 + coalesce('".$row['a_d120']."', 0) * 135 +
					coalesce('".$row['a_d150']."', 0) * 175 + coalesce('".$row['a_d200']."', 0) * 250 + coalesce('".$row['a_d300']."', 0) * 300) /
				     (coalesce('".$row['a_d50']."', 0) + coalesce('".$row['a_d70']."', 0) + coalesce('".$row['a_d90']."', 0) + coalesce('".$row['a_d120']."', 0) +
					coalesce('".$row['a_d150']."', 0) + coalesce('".$row['a_d200']."', 0) + coalesce('".$row['a_d300']."', 0))),
				     0),
				 if((coalesce('".$row['b_d50']."', 0) + coalesce('".$row['b_d70']."', 0) + coalesce('".$row['b_d90']."', 0) + coalesce('".$row['b_d120']."', 0) +
					coalesce('".$row['b_d150']."', 0) + coalesce('".$row['b_d200']."', 0) + coalesce('".$row['b_d300']."', 0)) > 0,
				    ((coalesce('".$row['b_d50']."', 0) * 60 + coalesce('".$row['b_d70']."', 0) * 80 + coalesce('".$row['b_d90']."', 0) * 105 + coalesce('".$row['b_d120']."', 0) * 135 +
					coalesce('".$row['b_d150']."', 0) * 175 + coalesce('".$row['b_d200']."', 0) * 250 + coalesce('".$row['b_d300']."', 0) * 300) /
				     (coalesce('".$row['b_d50']."', 0) + coalesce('".$row['b_d70']."', 0) + coalesce('".$row['b_d90']."', 0) + coalesce('".$row['b_d120']."', 0) +
					coalesce('".$row['b_d150']."', 0) + coalesce('".$row['b_d200']."', 0) + coalesce('".$row['b_d300']."', 0))),
				     0)) * 100,
		`a_delay_avg_mult100` =
			if((coalesce('".$row['a_d50']."', 0) + coalesce('".$row['a_d70']."', 0) + coalesce('".$row['a_d90']."', 0) + coalesce('".$row['a_d120']."', 0) +
				coalesce('".$row['a_d150']."', 0) + coalesce('".$row['a_d200']."', 0) + coalesce('".$row['a_d300']."', 0)) > 0,
			   ((coalesce('".$row['a_d50']."', 0) * 60 + coalesce('".$row['a_d70']."', 0) * 80 + coalesce('".$row['a_d90']."', 0) * 105 + coalesce('".$row['a_d120']."', 0) * 135 +
				coalesce('".$row['a_d150']."', 0) * 175 + coalesce('".$row['a_d200']."', 0) * 250 + coalesce('".$row['a_d300']."', 0) * 300) /
			    (coalesce('".$row['a_d50']."', 0) + coalesce('".$row['a_d70']."', 0) + coalesce('".$row['a_d90']."', 0) + coalesce('".$row['a_d120']."', 0) +
				coalesce('".$row['a_d150']."', 0) + coalesce('".$row['a_d200']."', 0) + coalesce('".$row['a_d300']."', 0))),
			    0) * 100,
		`b_delay_avg_mult100` =
			if((coalesce('".$row['b_d50']."', 0) + coalesce('".$row['b_d70']."', 0) + coalesce('".$row['b_d90']."', 0) + coalesce('".$row['b_d120']."', 0) +
				coalesce('".$row['b_d150']."', 0) + coalesce('".$row['b_d200']."', 0) + coalesce('".$row['b_d300']."', 0)) > 0,
			   ((coalesce('".$row['b_d50']."', 0) * 60 + coalesce('".$row['b_d70']."', 0) * 80 + coalesce('".$row['b_d90']."', 0) * 105 + coalesce('".$row['b_d120']."', 0) * 135 +
				coalesce('".$row['b_d150']."', 0) * 175 + coalesce('".$row['b_d200']."', 0) * 250 + coalesce('".$row['b_d300']."', 0) * 300) /
			    (coalesce('".$row['b_d50']."', 0) + coalesce('".$row['b_d70']."', 0) + coalesce('".$row['b_d90']."', 0) + coalesce('".$row['b_d120']."', 0) +
				coalesce('".$row['b_d150']."', 0) + coalesce('".$row['b_d200']."', 0) + coalesce('".$row['b_d300']."', 0))),
			    0) * 100,
		`delay_cnt` =
			GREATEST(coalesce('".$row['a_d50']."', 0) + coalesce('".$row['a_d70']."', 0) + coalesce('".$row['a_d90']."', 0) + coalesce('".$row['a_d120']."', 0) +
					coalesce('".$row['a_d150']."', 0) + coalesce('".$row['a_d200']."', 0) + coalesce('".$row['a_d300']."', 0),
				 coalesce('".$row['b_d50']."', 0) + coalesce('".$row['b_d70']."', 0) + coalesce('".$row['b_d90']."', 0) + coalesce('".$row['b_d120']."', 0)+
					coalesce('".$row['b_d150']."', 0) + coalesce('".$row['b_d200']."', 0) + coalesce('".$row['b_d300']."', 0)),
		`a_delay_cnt` =
			coalesce('".$row['a_d50']."', 0) + coalesce('".$row['a_d70']."', 0) + coalesce('".$row['a_d90']."', 0) + coalesce('".$row['a_d120']."', 0)+
				coalesce('".$row['a_d150']."', 0) + coalesce('".$row['a_d200']."', 0) + coalesce('".$row['a_d300']."', 0),
		`b_delay_cnt` =
			coalesce('".$row['b_d50']."', 0) + coalesce('".$row['b_d70']."', 0) + coalesce('".$row['b_d90']."', 0) + coalesce('".$row['b_d120']."', 0)+
				coalesce('".$row['b_d150']."', 0) + coalesce('".$row['b_d200']."', 0) + coalesce('".$row['b_d300']."', 0),

		`rtcp_avgfr_mult10` =
			ROUND(
			if('".$row['a_rtcp_avgfr']."' <> '' OR '".$row['b_rtcp_avgfr']."' <> '',
			   (coalesce('".$row['a_rtcp_avgfr,']."', 0) + coalesce('".$row['b_rtcp_avgfr,']."', 0)) / 2 * 10,
			   NULL)),        `rtcp_avgjitter_mult10` =
			ROUND(                if('".$row['a_rtcp_avgjitter']."' <> '' OR '".$row['b_rtcp_avgjitter']."' <> '',
			   (coalesce('".$row['a_rtcp_avgjitter,']."', 0) + coalesce('".$row['b_rtcp_avgjitter,']."', 0)) / 2 * 10,
			   NULL)),
		`lost` = if('".$row['a_lost']."' <> '' OR '".$row['b_lost']."' <> NULL,
			    GREATEST('".$row['a_lost,']."', '".$row['b_lost,']."', 0),
			    NULL)

		";
		
		$res2 = mysql_query($query);
		if (!$res2) {
	#		echo $query."\n";
			die('Invalid query '.($query).': ' . mysql_error());
		}

		$query = "INSERT INTO cdr_next SET cdr_ID = ".$row['ID'].", custom_header1 = '".$row['custom_header1']."', fbasename = '".$row['fbasename']."'";
		$res2 = mysql_query($query);
		if (!$res2) {
	#		echo $query."\n";
			die('Invalid query '.($query).': ' . mysql_error());
		}

#		echo $row['ID']."\n";
		$i++;
	}
	#if($i < 1000) break;
}
#mysql_query("COMMIT;");
$pass = "";
if(PASS == "") {
	$pass = "-p".PASS;
}

mysql_query("SET unique_checks=1;");
mysql_query("SET foreign_key_checks=1;");


?>
