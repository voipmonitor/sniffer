IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'voipmonitor')
	create database voipmonitor;
GO

use voipmonitor;

-- IF EXISTS (SELECT * FROM sys.objects WHERE name = 'filter_ip')
-- 	drop TABLE filter_ip;
-- IF EXISTS (SELECT * FROM sys.objects WHERE name = 'filter_telnum')
-- 	drop TABLE filter_telnum;
-- IF EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr')
-- 	drop TABLE cdr;
-- IF EXISTS (SELECT * FROM sys.objects WHERE name = 'register')
-- 	drop TABLE register;3
-- GO

IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'filter_ip')
CREATE TABLE filter_ip (
  id int PRIMARY KEY IDENTITY,
  ip bigint default NULL,
  mask int default NULL,
  direction tinyint default 0,
  rtp tinyint default '0',
  sip tinyint default '0',
  register tinyint default '0',
  graph tinyint default '0',
  wav tinyint default '0',
  note TEXT
);

IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'filter_telnum')
CREATE TABLE filter_telnum (
  id int PRIMARY KEY IDENTITY,
  prefix bigint default NULL,
  fixed_len bigint default 0,
  direction tinyint default 0,
  rtp tinyint default '0',
  sip tinyint default '0',
  register tinyint default '0',
  graph tinyint default '0',
  wav tinyint default '0',
  note TEXT
);

IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr')
CREATE TABLE cdr (
  ID bigint PRIMARY KEY IDENTITY,
  calldate datetime NOT NULL,
  callend datetime NOT NULL,
  duration bigint NOT NULL,
  connect_duration bigint NOT NULL,
  progress_time bigint NOT NULL,
  first_rtp_time bigint NOT NULL,
  caller varchar(255) NOT NULL,
  caller_domain varchar(255) NOT NULL,
  caller_reverse varchar(255) NOT NULL,
  callername varchar(255) NOT NULL,
  callername_reverse varchar(255) NOT NULL,
  called varchar(255) NOT NULL,
  called_domain varchar(255) NOT NULL,
  called_reverse varchar(255) NOT NULL,
  sipcallerip bigint NOT NULL,
  sipcalledip bigint NOT NULL,
  custom_header1 varchar(255) DEFAULT NULL,
  fbasename varchar(255) NOT NULL,
  whohanged char(10) DEFAULT NULL,
  bye tinyint NOT NULL default 2,
  lastSIPresponse varchar(128) default NULL,
  lastSIPresponseNum int default NULL,
  sighup tinyint NOT NULL default 0,
  a_index smallint NOT NULL default 0,
  b_index smallint NOT NULL default 0,
  a_payload int NOT NULL default 0,
  b_payload int NOT NULL default 0,
  a_saddr bigint NOT NULL default 0,
  b_saddr bigint NOT NULL default 0,
  a_received bigint NOT NULL default 0,
  b_received bigint NOT NULL default 0,
  a_lost bigint NOT NULL default 0,
  b_lost bigint NOT NULL default 0,
  a_ua varchar(1024) NULL,
  b_ua varchar(1024) NULL,
  a_avgjitter float(32) NOT NULL default 0,
  b_avgjitter float(32) NOT NULL default 0,
  a_maxjitter float(32) NOT NULL default 0,
  b_maxjitter float(32) NOT NULL default 0,
  a_sl1 bigint NOT NULL default 0,
  a_sl2 bigint NOT NULL default 0,
  a_sl3 bigint NOT NULL default 0,
  a_sl4 bigint NOT NULL default 0,
  a_sl5 bigint NOT NULL default 0,
  a_sl6 bigint NOT NULL default 0,
  a_sl7 bigint NOT NULL default 0,
  a_sl8 bigint NOT NULL default 0,
  a_sl9 bigint NOT NULL default 0,
  a_sl10 bigint NOT NULL default 0,
  a_d50 bigint NOT NULL default 0,
  a_d70 bigint NOT NULL default 0,
  a_d90 bigint NOT NULL default 0,
  a_d120 bigint NOT NULL default 0,
  a_d150 bigint NOT NULL default 0,
  a_d200 bigint NOT NULL default 0,
  a_d300 bigint NOT NULL default 0,
  b_sl1 bigint NOT NULL default 0,
  b_sl2 bigint NOT NULL default 0,
  b_sl3 bigint NOT NULL default 0,
  b_sl4 bigint NOT NULL default 0,
  b_sl5 bigint NOT NULL default 0,
  b_sl6 bigint NOT NULL default 0,
  b_sl7 bigint NOT NULL default 0,
  b_sl8 bigint NOT NULL default 0,
  b_sl9 bigint NOT NULL default 0,
  b_sl10 bigint NOT NULL default 0,
  b_d50 bigint NOT NULL default 0,
  b_d70 bigint NOT NULL default 0,
  b_d90 bigint NOT NULL default 0,
  b_d120 bigint NOT NULL default 0,
  b_d150 bigint NOT NULL default 0,
  b_d200 bigint NOT NULL default 0,
  b_d300 bigint NOT NULL default 0,
  a_mos_f1 float(8) NOT NULL default 0,
  a_mos_f2 float(8) NOT NULL default 0,
  a_mos_adapt float(8) NOT NULL default 0,
  a_lossr_f1 float(8) NOT NULL default 0,
  a_lossr_f2 float(8) NOT NULL default 0,
  a_lossr_adapt float(8) NOT NULL default 0,
  a_burstr_f1 float(8) NOT NULL default 0,
  a_burstr_f2 float(8) NOT NULL default 0,
  a_burstr_adapt float(8) NOT NULL default 0,
  b_mos_f1 float(8) NOT NULL default 0,
  b_mos_f2 float(8) NOT NULL default 0,
  b_mos_adapt float(8) NOT NULL default 0,
  b_lossr_f1 float(8) NOT NULL default 0,
  b_lossr_f2 float(8) NOT NULL default 0,
  b_lossr_adapt float(8) NOT NULL default 0,
  b_burstr_f1 float(8) NOT NULL default 0,
  b_burstr_f2 float(8) NOT NULL default 0,
  b_burstr_adapt float(8) NOT NULL default 0,
  a_rtcp_loss int(8) DEFAULT NULL,
  a_rtcp_maxfr int(8)DEFAULT NULL,
  a_rtcp_avgfr float(8)DEFAULT NULL,
  a_rtcp_maxjitter int(8)DEFAULT NULL,
  a_rtcp_avgjitter float(8)DEFAULT NULL,
  b_rtcp_loss int(8) DEFAULT NULL,
  b_rtcp_maxfr int(8) DEFAULT NULL,
  b_rtcp_avgfr float(8) DEFAULT NULL,
  b_rtcp_maxjitter int(8) DEFAULT NULL,  
  b_rtcp_avgjitter float(8) DEFAULT NULL
);
CREATE INDEX calldate ON cdr (calldate);
CREATE INDEX callend ON cdr (callend);
CREATE INDEX duration ON cdr (duration);
CREATE INDEX source ON cdr (caller);
CREATE INDEX source_reverse ON cdr (caller_reverse);
CREATE INDEX destination ON cdr (called);
CREATE INDEX destination_reverse ON cdr (called_reverse);
CREATE INDEX callername ON cdr (callername);
CREATE INDEX callername_reverse ON cdr (callername_reverse);
CREATE INDEX sipcallerip ON cdr (sipcallerip);
CREATE INDEX sipcalledip ON cdr (sipcalledip);
CREATE INDEX lastSIPresponse ON cdr (lastSIPresponse);
CREATE INDEX lastSIPresponseNum ON cdr (lastSIPresponseNum);
CREATE INDEX bye ON cdr (bye);
CREATE INDEX a_saddr ON cdr (a_saddr);
CREATE INDEX b_saddr ON cdr (b_saddr);
CREATE INDEX a_lost ON cdr (a_lost);
CREATE INDEX b_lost ON cdr (b_lost);
CREATE INDEX a_avgjitter ON cdr (a_avgjitter);
CREATE INDEX b_avgjitter ON cdr (b_avgjitter);
CREATE INDEX a_maxjitter ON cdr (a_maxjitter);
CREATE INDEX b_maxjitter ON cdr (b_maxjitter);
CREATE INDEX a_mos_f1 ON cdr (a_mos_f1);
CREATE INDEX a_mos_f2 ON cdr (a_mos_f2);
CREATE INDEX a_mos_adapt ON cdr (a_mos_adapt);
CREATE INDEX b_mos_f1 ON cdr (b_mos_f1);
CREATE INDEX b_mos_f2 ON cdr (b_mos_f2);
CREATE INDEX b_mos_adapt ON cdr (b_mos_adapt);

IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'register')
CREATE TABLE register (
  ID bigint PRIMARY KEY IDENTITY,
  calldate datetime NOT NULL,
  sipcallerip bigint NOT NULL,
  sipcalledip bigint NOT NULL,
  fbasename varchar(255) NOT NULL,
  sighup tinyint NOT NULL default 0
);
CREATE INDEX calldate ON register (calldate);
CREATE INDEX sipcallerip ON register (sipcallerip);
CREATE INDEX sipcalledip ON register (sipcalledip);

GO

-- functions

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'concat' AND type = 'FN')
	DROP FUNCTION dbo.concat
GO
CREATE FUNCTION dbo.concat(@str1 VARCHAR(MAX),@str2 VARCHAR(MAX))
RETURNS VARCHAR(MAX) AS
BEGIN
	RETURN @str1 + @str2
END
GO

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'trim' AND type = 'FN')
	DROP FUNCTION dbo.trim
GO
CREATE FUNCTION dbo.trim(@str VARCHAR(MAX))
RETURNS VARCHAR(MAX) AS
BEGIN
	RETURN LTRIM(RTRIM(@str))
END
GO

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'div' AND type = 'FN')
	DROP FUNCTION dbo.div
GO
CREATE FUNCTION dbo.div(@oper1 FLOAT,@oper2 FLOAT)
RETURNS FLOAT AS
BEGIN
	RETURN CASE WHEN (@oper2 is NULL or @oper2=0) THEN NULL ELSE @oper1/@oper2 END;
END
GO

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'iif' AND type = 'FN')
	DROP FUNCTION dbo.iif
GO
CREATE FUNCTION dbo.iif(@rsltCond VARCHAR(MAX),@rslt1 VARCHAR(MAX),@rslt2 VARCHAR(MAX))
RETURNS FLOAT AS
BEGIN
	RETURN CAST((CASE WHEN (@rsltCond is not NULL and @rsltCond<>0) THEN @rslt1 ELSE @rslt2 END) as FLOAT);
END
GO

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'greatest' AND type = 'FN')
	DROP FUNCTION dbo.greatest
GO
CREATE FUNCTION dbo.greatest(@par1 FLOAT,@par2 FLOAT)
RETURNS FLOAT AS
BEGIN
	RETURN CASE WHEN @par1>@par2 THEN @par1 ELSE coalesce(@par2, @par1) END;
END
GO

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'least' AND type = 'FN')
	DROP FUNCTION dbo.least
GO
CREATE FUNCTION dbo.least(@par1 FLOAT,@par2 FLOAT)
RETURNS FLOAT AS
BEGIN
	RETURN CASE WHEN @par1<@par2 THEN @par1 ELSE coalesce(@par2, @par1) END;
END
GO

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'inet_aton' AND type = 'FN')
	DROP FUNCTION dbo.inet_aton;
GO
CREATE FUNCTION dbo.inet_aton (@ipstr VARCHAR(15))
RETURNS BIGINT AS 
BEGIN
	RETURN CAST(
		CAST((256*256*256) as BIGINT) * PARSENAME(@ipstr, 4) + 
		256*256 * PARSENAME(@ipstr, 3) + 
		256 * PARSENAME(@ipstr, 2) + 
		1 * PARSENAME(@ipstr, 1) AS BIGINT);
END
GO

IF EXISTS (SELECT name FROM sys.objects WHERE name = 'inet_ntoa' AND type = 'FN')
	DROP FUNCTION dbo.inet_ntoa
GO
CREATE FUNCTION dbo.inet_ntoa(@ipnumber BIGINT)
RETURNS VARCHAR(15) AS
BEGIN
	RETURN CAST(
		CAST(@ipnumber/(256*256*256) as VARCHAR(3)) + '.' +
		CAST(@ipnumber%(256*256*256)/(256*256) as VARCHAR(3)) + '.' +
		CAST(@ipnumber%(256*256)/(256) as VARCHAR(3)) + '.' +
		CAST(@ipnumber%256 as VARCHAR(3)) as VARCHAR(15));
END
GO
