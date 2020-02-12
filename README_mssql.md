# MS SQL configuration

## example configuration:

	server: 	192.192.1.101
	ms sql port:	1433 (default port)
	database:	voipmonitor
	username: 	sa
	password: 	abc123

## config sniffer:

	install: unixODBC, unixODBC-devel (for compile voipmonitor), freetds

	/etc/odbc.ini (append / modify)
		
		[voipmonitor]
		Server          = 192.168.1.101
		Port            = 1433
		Database        = voipmonitor
		Driver          = /usr/lib64/libtdsodbc.so.0

		#Note: /usr/lib64/libtdsodbc.so.0 is library contained in package freetds; please specify correct path and filename

	/etc/voipmonitor.conf 

		odbsdsn = voipmonitor
		odbcuser = sa
		odbcpass = abc123
		odbcdriver = mssql

		sqldriver = odbc

## config web-gui:

	install: php-mssql

	[web gui folder]/configuration.php (append / modify)

		define("SQL_DRIVER", "mssql");
		define("SQL_CDRTABLE", "cdr");

		define("MSSQL_HOST", "192.168.1.101");
		define("MSSQL_DB", "voipmonitor");
		define("MSSQL_USER", "sa");
		define("MSSQL_PASS", "abc123");
