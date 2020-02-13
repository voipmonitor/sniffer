# RRD

1. Collecting stats into rrd files and creating graphs (note:rrd files will be automaticaly saved into your spool directory into subdir rrd)
	1. **Prerequisite**: Installed librrd and rrdtool in your OS
	2. in voipmonitor.conf check for option 'rrd' and set it to yes (default is yes) rrd = yes


```
I) For debian 7 based systems:
i) apt-get install rrdtool
*) if you compiling voipmonitor from sources: apt-get install rrdtool-dev 

II) Red Hat
i) yum install rrdtool

III) For centOS 
i)you need rpmForge repositiories downloaded and installed. If you don't have follow instructions from: 
	http://wiki.centos.org/AdditionalResources/Repositories/RPMForge

ii)Finally install rrd tools
	1) For x86_64 download
		# yum install rrdtool.x86_64
	2) Otherwise
		# yum install rrdtool.i686
```


2. How to create graphs from collected data ?
	1. You can ask voipmonitor's manager to do it
	2. You can create graphs that meets your specific needs using 'rrdtool graph'. For its syntax look at: http://oss.oetiker.ch/rrdtool/doc/rrdgraph.en.html

```

I) recheck manager's setting in your voipmonitor.conf
i) listen only for localhost connection (see option managerip = 127.0.0.1)
ii) and at default port 5029 (see option managerport = 5029)

II) connect to voipmonitor's manager using telnet and check for available option for creategraph command
i) in your shell enter:
	# telnet 127.0.0.1 5029
ii) You will see something like this after successfull connect:
	Trying 127.0.0.1...
	Connected to localhost.localdomain (127.0.0.1).
	Escape character is '^]'.
iii) Enter 
	creategraph
iv) If you will see folllowing line, creategraph option is supported in your manager:
	Syntax: creategraph graph_type linuxTS_from linuxTS_to size_x_pixels size_y_pixels  [ slope-mode  [ icon-mode  [ color  [ dstfile ]]]]
v) You can connect again and issue commands bellow 
	creategraph PS now-2weeks now 600 400 0 0 - /tmp/graph_PS.png
	creategraph SQLq now-2weeks now 600 400 0 0 - /tmp/graph_SQLq.png
	creategraph tCPU now-2weeks now 600 400 0 0 - /tmp/graph_tCPU.png
	creategraph drop now-2weeks now 600 400 0 0 - /tmp/graph_drop.png
	creategraph speed now-2weeks now 600 400 0 0 - /tmp/graph_speed.png
	creategraph heap now-2weeks now 600 400 0 0 - /tmp/graph_heap.png
	creategraph calls now-2weeks now 600 400 0 0 - /tmp/graph_calls.png
	creategraph tacCPU now-2weeks now 600 400 0 0 - /tmp/graph_tacCPU.png

*) Last example sends PNG image to stdout instead of saving it into a file.
	creategraph mem_usage "31.8.2014 00:00" now 600 400
```
Suggestion: rrd files are located in you spool directory in subdir 'rrd'


3. APPENDIX creategraph syntax and its arguments:

```
Syntax:
	creategraph graph_type linuxTS_from linuxTS_to size_x_pixels size_y_pixels  [ slope-mode  [ icon-mode  [ color  [ dstfile ]]]] 

	Arguments:
	graphType is one of the following:
		PS PSC PSS PSSM PSSR PSR PSA SQLq SQLf tCPU drop speed heap calls tacCPU memusage loadavg

	linuxTS_from linuxTS_to
		both arguments are at-style time format
		for example from Aug-12-2014 to now: "12.8.2014 22:00" now
		for example from 2 weeks ago, to 1 week ago: "now-2weeks" "now-1week"

	size_x_pixels size_y_pixels
		Determines final resolution in pixels of graph image. Minimal setting is: 400 200
		Beware: If you choose lower resolution than 400 for x-axis or 200 for y-axis resulting graph will be treated as icon. (read bellow)

	[slope-mode]
		Put 1, if you want to have slope curves. Default is 0

	[icon-mode]
		Put 1, if you want only fillings of graph (no descriptions no axis no lines only fill). Default 0
	[color]
		Define color of outgoing graph. Use '-' sign to let rrd choose color for you
	[dstfile]
		Specifies file to which you want to save the graph.
		Default is sending image to stdout.
		If you want to send image on stdout, skip this argument.
```

* arguments in square brackets are optional, if you don't define them, default values are used.
