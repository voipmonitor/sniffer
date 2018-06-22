#!/bin/bash
#cloudToken=
__VERSION=1.0m

#__COLORS=1	#automagicaly set by checkTput function
			#0 for disable colors output
			#1 for enable colors
if [ $# -eq 1 ]; then
	__VERBOSE=1
else
	__VERBOSE=0
fi

function welcome {
	clear
	echo "$(prints "Welcome")$(printn " to")$(printps " voipmonitor cloud")$(printn " installation script version ")$(printp "$__VERSION")"
	echo
	echo
	oIFS="$IFS"
}

function trap_command {
	#reseting color and IFS and echo resetting for undefined behaviour when CTRL-C is presed inside "read -s" command when CTRL+C is pressed and exit
	if [ "del$tempDir" != "del" ]; then
		removeDir "$tempDir"
	fi

	echo $(printn "Exitting..")
	stty echo
	IFS=$oIFS
	exit 130
}

function exit_command {
	#reseting color and IFS and echo resetting for undefined behaviour when CTRL-C is presed inside "read -s" command when CTRL+C is pressed and exit
	if [ "ok$1" == "ok0" ]; then
		 echo $(printn "Installation done.")
	else
		 echo $(printn "Script exited abnormally...")
	fi
	#stty echo
	IFS=$oIFS
	exit $1
}

function prints {
	if [ $__COLORS -eq 1 ]; then
		echo "$(tput sgr 0)$(tput bold)$(tput setaf 7)$1"
	else
		echo "$1"
	fi
}

#print possible selected
function printps {
	if [ $__COLORS -eq 1 ]; then
		echo "$(tput sgr 0)$(tput bold)$(tput setaf 2)$1"
	else
		echo "$1"
	fi
}

#print possible
function printp {
	if [ $__COLORS -eq 1 ]; then
		echo "$(tput sgr 0)$(tput setaf 2)$1"
	else
		echo "$1"
	fi
}

#print impossible
function printz {
	if [ $__COLORS -eq 1 ]; then
		echo "$(tput sgr 0)$(tput setaf 1)$1"
	else
		echo "$1"
	fi
}

#print neutral
function printn {
	if [ $__COLORS -eq 1 ]; then
		echo "$(tput sgr0)$1"
	else
		echo "$1"
	fi
}

function checkBitSize {	
	result=$1
	local mu=$(uname -m 2> /dev/null)
	local retval=$?

	if [ $retval -eq 0 ]; then
		if [ "ahoj $mu" == "ahoj x86_64" ]; then 
			#echo "Find 64-bit OS architecture"
			local def="64bit"
			local bit64=1
		else
			local def="32bit"
			local bit64=0
		fi

#		if ask2 "Can you confirm your OS architecture? " "64bit" "32bit" "$def"; then
#			local bit64=1
#		else
#			local bit64=0
#		fi
	else
		if ask2 "Probing failed. Please select your OS architecture." "64bit" "32bit"; then
			local bit64=1
		else
			local bit64=0
		fi
	fi
    eval $result="'$bit64'"
}

function checkTput {
	tp=$(which tput 2> /dev/null)
	retval=$(echo $?)

	if [ $retval -eq 0 ]; then
		__COLORS=1
	else
		__COLORS=0
	fi
}

function checkWget {
	local _command="wget"
	local _tp=$(which $_command 2> /dev/null)

	if [ "neni$_tp" == "neni" ]; then
		echo "$(printn "Sorry, but binary ")$(printp "$_command")$(printn " was ")$(printz "not found")$(printn ". Please install ")$(printp "$_command")$(printn " or place it into your default path.")"
		echo "$(printn "	Directories that are defined in PATH variable: ")$(prints "$PATH")"
		echo
		echo "$(printn "Exitting")"
		exit 1
	else
		return 0
	fi
}

function checkVoipmonitor {
    local _result=$1
    local _command="voipmonitor"
    which "$_command"
    local _retval=$?

    if [ "no$_retval" == "no0" ]; then
        getVoipmonitorVersion _version
        eval $_result="'${_version}'"
        return 0
    else
        eval $_result="'00_NotAvailable'"
        return 1
    fi
}

function getVoipmonitorVersion {
    local __result=$1
    local __version=$(voipmonitor|grep version|head -n1|cut -d ' ' -f3)

    if [ "no$__version" == "no" ]; then
        __version='00_NotAvailable'
    fi
    eval $__result="'${__version}'"
}

function getVoipmonitorDownloadableVersion {
	local helpfile='/tmp/voipmonitor-spider-probe.wget'
	local __resultLink=$1
	local __resultVersion=$2
	local __resultFile=$3
	local _oldVersion=$4
	local _install64bit=$5

	if [ "$_install64bit" == "1" ]; then 
		local bitprefix="64bit"
		local check="www.voipmonitor.org/current-stable-sniffer-static-64bit.tar.gz"
	else
		local bitprefix="32bit"
		local check="www.voipmonitor.org/current-stable-sniffer-static-32bit.tar.gz"
	fi
	echo "$(printn "Probing ")$(prints "voipmonitor.org")$(printn " for the latest static version. Please wait...")"

	local _command="--spider --timeout=10 --tries=2 $check"
	local _wgetline=$(wget $_command 2>&1|grep "\-static.tar.gz"|head -n1)
	local es="$?"
	case $es in
		"0" ) 
			local _linkstr="NA"
			local word
			# _wgetline is 'Přesměrováno na: http://sourceforge.net/projects/voipmonitor/files/10.0/voipmonitor-amd64-10.0.20-static.tar.gz/download [následuji]'
			# _wgetline is 'Platz: http://switch.dl.sourceforge.net/project/voipmonitor/10.1/voipmonitor-i686-10.1.23-static.tar.gz[folge]'
			for word in $_wgetline; do 
				local subword=${word::4}
				case $subword in 
					"http" )
						local _linkstr=$word
						break
					;;
					"ftp:" )
						local _linkstr=$word
						break
					;;
				esac
			done

			if [ "link$_linkstr" == "linkNA" ]; then
				echo "$(printn "Result is ")$(printz "Internal error: no link found, please contact voipmonitor support.")"
				exit_command 2
			fi

			#remove [platz] from _linkstr
			local _linkstr=`echo $_linkstr|sed 's/\[.*\]//'`

			# getting _versionstr its part before '-static.tar.' in link
			local controlstr=`echo $word|tr '-' ' '`
			local lastpart=''
			local _versionstr='';
			for part in $controlstr; do
				local subpart=${part::11}
				if [ "a$subpart" == "astatic.tar." ]; then
					local _versionstr=$lastpart
					break
				fi
				local lastpart=$part
			done
			
			# no version string found, try to continue
			if [ "version$_versionstr" == "version" ]; then
				echo "$(printz "Warning ")$(printn "Internal error: no version string found, if installation fail, please contact voipmonitor support.")"
				eval $__resultLink="'${_linkstr}'"
				eval $__resultVersion="'Unknown'"
				local _filestr="voipmonitor-static-$bitprefix-$_versionstr.tar.gz"
				eval $__resultFile="'${_filestr}'"
				return 1
			fi

			#no new version
			if [ "version$_versionstr" == "version$_oldVersion" ]; then
				echo "$(printn "Your voipmonitor version is ")$(prints "$_oldVersion")$(printn " and is the latest.")"
				eval $__resultLink="'${_linkstr}'"
				eval $__resultVersion="'${_versionstr}'"
				local _filestr="voipmonitor-static-$bitprefix-$_versionstr.tar.gz"
				eval $__resultFile="'${_filestr}'"
				return 1
			else
			#new verion found
				eval $__resultLink="'${_linkstr}'"
				eval $__resultVersion="'${_versionstr}'"
				local _filestr="voipmonitor-static-$bitprefix-$_versionstr.tar.gz"
				eval $__resultFile="'${_filestr}'"
				return 0
			fi
        ;;
		"1" ) local message="$(printz "wget error:")$(printn " reached timeout for contacting download server.")";
        ;;
		"2" ) local message="$(printz "wget error:")$(printn " unrecognized option, please get new version of wget.")";
		;;
		"4" ) local message="$(printz "wget error:")$(printn "Server voipmonitor.org is unaccessible, try again later.")";
		;;
		"8" ) local message="$(printz "wget error:")$(printn " Last build disappeared from web, please contact voipmonitor support.")";
		;;
		*   ) local message="$(printz "wget error:")$(printn" unknown wget return status. (")$(pintz "$es")";
	esac
	echo "$(printn "Result is ")$message)"
	exit_command 1
}

function downloadFromLink {

	local _linkname=$1
	local _filename=$2

	echo "Downloading the latest version into $(printp "$_filename")$(printn ", please wait...")"
	echo "$(printn "$_linkname")"
	echo 
	echo "Please wait."

	#echo "wget $newLink -O $fileName"
	if [ $__VERBOSE -eq 1 ]; then
		cmd "wget -O" "$_filename" "$_linkname" "--no-check-certificate"
	else
		cmd "wget --no-check-certificate -q -O" "$_filename" "$_linkname"
	fi


	downloadReturned=$?
	if [ "a$downloadReturned" != "a0" ]; then
		echo "$(printz "Problem during downloading")"
		echo
		exit_command 2
	else
		echo "$(printps "Success")"
	fi
}

function cmd {

	#TODO: Fix that star '*' can be only at end of second argument
	local arg2=$2
	local lPos=$((${#arg2}-1))
	local charAtEnd=${arg2:$lPos:1}
	local star=""
	
	if [ $# -ge 2 ]; then 
		if [ "$charAtEnd" = "*" ]; then
			local star="*"
			local arg2=${arg2:0:$lPos}
		fi
	fi

	if [ $__VERBOSE -eq 1 ]; then
		echo "$(prints "Exe")$(printn "cuting command: ")$(printp "$1 $2 $3 $4 $5")$(printn "")";
		case "$#" in 
			"1" ) $1;;
			"2" ) $1 "$arg2"$star ;;
			"3" ) $1 "$arg2"$star "$3";;
			"4" ) $1 "$arg2"$star "$3" "$4";;
			*) exit_command 4;;
		esac
	else
		case "$#" in 
			"1" ) $1 >/dev/null 2>&1 ;;
			"2" ) $1 "$arg2"$star >/dev/null 2>&1 ;;
			"3" ) $1 "$arg2"$star "$3" >/dev/null 2>&1 ;;
			"4" ) $1 "$arg2"$star "$3" "$4" >/dev/null 2>&1 ;;
			*) exit_command 4;;
		esac
	fi
	local result=$?

	if [ "a$result" != "a0" ]; then
		echo "$(printz "Problem")$(printn " while processing command '")$(printp " $1 $2 $3 $4")"
		echo "$(printn "Returned error code: ")$(printz "$result")"
		exit_command 3
	fi
}

function cmdu {
	#TODO: Fix that star '*' can be only at end of second argument
	local arg2=$2
	local lPos=$((${#arg2}-1))
	local charAtEnd=${arg2:$lPos:1}
	local star=""
	
	if [ $# -ge 2 ]; then 
		if [ "$charAtEnd" = "*" ]; then
			local star="*"
			local arg2=${arg2:0:$lPos}
		fi
	fi
	if [ $__VERBOSE -eq 1 ]; then
		echo "$(prints "Exe")$(printn "cuting command: ")$(printp "$1 $2 $3 $4 $5")$(printn "")";
		case "$#" in 
			"1" ) $1;;
			"2" ) $1 "$arg2"$star ;;
			"3" ) $1 "$arg2"$star "$3";;
			"4" ) $1 "$arg2"$star "$3" "$4";;
			*) exit_command 4;;
		esac
	else
		case "$#" in 
			"1" ) $1 >/dev/null 2>&1 ;;
			"2" ) $1 "$arg2"$star >/dev/null 2>&1 ;;
			"3" ) $1 "$arg2"$star "$3" >/dev/null 2>&1 ;;
			"4" ) $1 "$arg2"$star "$3" "$4" >/dev/null 2>&1 ;;
			*) exit_command 4;;
		esac
	fi
}

function createTempDir {
	local _tempDir=$1
	verbosen "$(printn "Creating")$(prints " temporary")$(printn " directory ") "
	local newDir=`mktemp -d 2> /dev/null`
	if [ "no$newDir" == "no" ]; then
		echo "$(printz "FAILED")"
		exit_command 4
	else
		verbose "$(printp "$newDir")"
	fi
	eval $_tempDir="'${newDir}'"
}

function removeDir {
	local rmDir="$1"
	verbose "$(printn "Removing directory ")$(printp "$rmDir")$(printn "") "
	cmd "rm -r" "$rmDir"
}

function verbosen {
	if [ $__VERBOSE -eq 1 ]; then
		echo -n "$1"
	fi
}

function verbose {
	if [ $__VERBOSE -eq 1 ]; then
		echo "$1"
	fi
}

function installFromFile {

	local _configFile=$1
	local _oldConfigFile=$2
	local filename=$3
	local destdir=$4

	local dir=`pwd`
	local subdir=unpacked

	verbose "$(printn "Entering ")$(printp "$destdir")"
	cd $destdir
	verbose "$(printn "Making dir ")$(printp "$destdir/$subdir")"
	cmd "mkdir" "$subdir"
	verbose
	
	verbose "$(printn "Entering ")$(printp "$destdir/$subdir")"
	cd $destdir/$subdir

	verbose "$(printn "Unpacking files into ")$(printp "$destdir/$subdir")"
	verbose "$(printn "Unpacking from file ")$(printp "$filename")$(printn "")"
	cmd "tar -xzf" "$filename"
	verbose

	inDir=`ls -1|head -n1`
	verbose "$(printn "Entering ")$(printp "$inDir")"
	cd "$inDir"
	verbose

	echo "Checking if "$(prints "voipmonitor")$(printn " is running");
	local killing="no";
	local round=0;
	local lastkill

	while true; do
		local vmpid=`pgrep -x voipmonitor|head -n1`
		if [ "a$vmpid" != "a" ]; then
			if [ "a$lastkill" == a$vmpid ]; then 
				if [ $round -gt 30 ]; then
					echo
					echo "$(printz "Can not kill")$(printn " voipmonitor with PID ")$(printp "$lastkill")$(printn ", please ")$(printp "stop manually")$(prints " voipmonitor.")"
					exit_command 2
				else
					echo -n '.'
					sleep 1
					local round=$(( round + 1 ))
				fi
			else
				if ask2 "Would you like to kill voipmonitor process with PID $(prints "$vmpid")$(printn "?")" "yes" "no" "yes"; then 
					echo -n "$(printz "Killing")$(printn " voipmonitor with PID ")$(prints "$vmpid")"$(printn " ");
					local round=1
					local killing="yes"
					local lastkill=$vmpid
					kill $vmpid
					sleep 1
				else
					echo
					echo "Can not continue, please stop voipmonitor manually"
					exit_command 2
				fi
			fi
		else
			if [ "$killing" == "yes" ]; then
				echo 
				echo "$(printn "voipmonitor successfully ")$(printp "killed")$printn ".")";
				echo
			else
				echo "$(printn "voipmonitor is ")$(printp "not running")$(printn ".")";
				echo
			fi
			break
		fi
	done

	verbose
	#verbose "Installing /usr/local/share/voipmonitor/audio"
	#cmd "mkdir -p" "/usr/local/share/voipmonitor/audio"

	#cmd "cp" "usr/local/share/voipmonitor/audio/*" "/usr/local/share/voipmonitor/audio/"

	echo "Installing voipmonitor $(printp "binary")$(printn " to ")$(printp "/usr/local/sbin/voipmonitor")"
	cmdu "mkdir" "-p" "/usr/local/sbin"
	cmd "cp" "usr/local/sbin/voipmonitor" "/usr/local/sbin/voipmonitor"
	

	if [ "$installedVoipmonitor" == "1" ]; then
		verbosen "$(printn "Creating ")$(printn "temporary-file ")"
		local __oldTmpConfigFile=$(mktemp 2>/dev/null)
		if [ "no$__oldTmpConfigFile" = "no" ];then
			echo "$(printz "FAILED")"
			exit_command 4
		fi
		DATE=`date +'%Y-%m-%d_%H:%M' 2>/dev/null`
		local __oldConfigFile=/etc/voipmonitor_$DATE_${__oldTmpConfigFile:5:${#__oldTmpConfigFile}}.conf
		verbose "$(printp "$__oldTmpConfigFile")$(printn "")"

		cmd "mv" "$__oldTmpConfigFile" "$__oldConfigFile"

		verbose "$(printn "Backuping your ")$(printp "/etc/voipmonitor.conf")$(printn " to ")$(printp "$__oldConfigFile")$(printn ".")"
		verbose "$(printn "Installing new ")$(printp "voipmonitor.conf")$(printn " to ")$(printp "/etc/voipmonitor.conf")$(printn ".")"

		#non existence of old config file cannot cause instalator to say bye using cmdu
		cmdu "mv" "/etc/voipmonitor.conf" "$__oldConfigFile"

		local __configFile="$destdir/$subdir/$inDir/etc/voipmonitor.conf"
	else
		verbose "$(printn "Installing new ")$(printp "voipmonitor.conf")$(printn " to ")$(printp "/etc/voipmonitor.conf")"
		local __configFile="$destdir/$subdir/$inDir/etc/voipmonitor.conf"
		local __oldConfigFile="NA"
	fi

	#showing where are config file located
	echo
	if [ $installedVoipmonitor -eq 1 ]; then
		echo "$(prints "Old config")$(printn " file is backuped in ")$(printp "$__oldConfigFile")"
	fi
	verbose "$(prints "New config")$(printn " file is placed in ")$(printp "$__configFile")$(printn "")" 
	echo "$(prints "New config")$(printn " file will be placed in ")$(printp "/etc/voipmonitor.conf")$(printn ".")"
	echo "Please $(prints "check")$(printn " configuration")$(printn " and ")$(prints "edit it")$(printn " for your needs.") " 


	echo
	if ask2 "Would you like to start voipmonitor on each server boot? " "yes" "no" "yes"; then
		verbose "Installing etc/init.d/voipmonitor starting script to $(printp "/etc/init.d/voipmonitor")$(printn ". You can start voipmonitor by ")$(printp "/etc/init.d/voipmonitor start")"
		cmd "cp" "etc/init.d/voipmonitor" "/etc/init.d/"
		verbose -n "$(printn "Setting init.d script into default runlevels")"
		update-rc.d voipmonitor defaults >/dev/null 2>&1
		local result=$?
		if [ "ok$result" != "ok0" ] ; then
			if [ "ok$result" == "ok127" ]; then
				cmd "chkconfig --add voipmonitor"
				cmd "chkconfig voipmonitor on"
			else
				echo "$(printn "Problem using command ")$(printp "update-rc.d voipmonitor defaults")$(printn " Returned error code: ")$(printz "$result")"
			fi
		fi
		initResult=1
	else
		initResult=0
	fi

	verbose
	verbose "$(printn "Returning into $dir .")"
	cd $dir

	#echo "hodnota1: $__configFile"
	#echo "hodnota2: $__oldConfigFile"

	eval $_configFile="'${__configFile}'"
	eval $_oldConfigFile="'${__oldConfigFile}'"
}


#Eliminate element's clones
function introvert {
	local __result=$1
	local arrayInLine="$2"
	local dst
	
	IFS=' ';
	for element in $arrayInLine; do
		local found="no"
		for dstelement in $dst; do
			if [ "is$element" == "is$dstelement" ]; then
				found="yes"
				break
			fi
		done
		if [ $found == "no" ]; then
			dst="$dst $element"
		fi
	done
	eval $__result="'${dst}'"
}

function getNetInterfaces {
    local result=$1
    local itemsInLine=$(tail -n +3 < /proc/net/dev|cut -d ':' -f1|tr -d ' '|tr "\n" " ")
    eval $result="'${itemsInLine}'"
}

function checkNetInterfaces {
    local iface
    local __ifup=$1
    local __ifdown=$2

    for iface in "${@:3}"; do
        local state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null);
        #echo $iface is in $state state
        case $state in
            "up" ) local ifup="$ifup $iface"
                ;;
            "down" ) local ifdown="$ifdown $iface"
                ;;
            "unknown" ) 
				local carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null);
				if [ "$carrier" == "1" ]; then
					local ifup="$ifup $iface"
				else
					local ifdown="$ifdown $iface"
				fi
                ;;
        esac

    done
    eval $__ifup="'${ifup}'"
    eval $__ifdown="'${ifdown}'"
}


function askPorts {
	local input="$1"
	local portBad=""
	local limitl=1
	local limith=65535

	echo "$(printn "what SIP ports do you use in your voip environment (example: 5060,5061) ")$(prints "[")$(printps "5060")$(prints "]")$(printn ".")"
	while true; do
		echo -n "$(prints "")"
		IFS=', ' read -p "Your selection : " -a array
		local arrInLine=${array[@]}
		if [ "def$arrInLine" == "def" ]; then
			local array[0]=5060
		fi

#check for inserted proper ports number
		local portBad=""
		for usrPort in "${array[@]}"; do
			#check for value is number, else redirect error to dev null
			if [ "$usrPort" -eq "$usrPort" ] 2>/dev/null; then
				#check port range
				if [ $usrPort -ge $limitl ]; then
					if [ $limith -lt $usrPort ]; then
						local portBad="$portBad $usrPort"
					fi
				else
					local portBad="$portBad $usrPort"
				fi
			else
				local portBad="$portBad $usrPort"
			fi
		done
		if [ "ok$portBad" == "ok" ]; then
			eval $input="'${array[@]}'"
			return 0
		else
			echo "$(printn "You entered wrong port ")$(printz "$portBad.")$(printn " Please select ports in range of ")$(printp "0 ")$(printn "-")$(printp " 65535")$(printn " or press ")$(printp "ENTER")$(printn " if you wish to use default SIP port ")$(prints "[")$(printps "5060")$(prints "]")$(printn ".")"
		fi
	done
}

function askToken {
	local _token="$1"
	local predefToken="$2"
	local question="$(printn "Please insert your ")$(printp "cloud token")$(printn ": ")$(prints "[")$(printps "$predefToken")$(prints "]") "
	echo -n "$question"
	read inserted
	echo -n $(printn "")

	if [ "a$inserted" == "a" ]; then
		local  inserted="$predefToken"
	fi
	eval $_token="'${inserted}'"
}

function askIfaces {
	local input="$1"
	local iup="$2"
	local idown="$3"
	local arrCheck="$idown $iup"
	local iBad=""

	echo "$(printn "On which ")$(printp "interface")$(printn "(")$(printp "s")$(printn ") would you like to run the sniffer?")"
	echo "$(printn "You can put a list of interfaces like eth0, eth1 or just a single interface eth0.")"
	while true; do
		if [ "ahoj$idown" != "ahoj" ]; then 
			echo "$(printn "You can choose from following interfaces :")"
			echo "$(printn " Active interfaces :   ")$(printp "$iup ")"
			echo "$(printn " Inactive interfaces : ")$(printz "$idown ")$(printn "(beware of choosing any interface which is down, it causes voipmonitor sniffer not to start)")"
		else
			echo "$(printn "You can choose from these interfaces : ")$(printp "$iup ")"
		fi

		echo -n "$(prints "")"
		IFS=', ' read -p "Your selection : " -a array

		local arrInLine=${array[@]}

#check for inserted proper interfaces
		local iBad=""
		for usrIface in "${array[@]}"; do
			local found="no"
			IFS=' ';
			for iface in $arrCheck; do
				if [ $usrIface == $iface ]; then
					local found="yes"
				fi
			done
			if [ $found == "no" ]; then
				local iBad="$iBad $usrIface"
			fi
		done
		if [ "ok$iBad" == "ok" ]; then
			if [ "ok$arrInLine" != "ok" ]; then
				eval $input="'${array[@]}'"
				return 0
			fi
		else
			echo "$(printn "You entered wrong interface ")$(printz "$iBad.")$(printn " Please choose only from available interfaces.")"
		fi
	done
}

#Function for create first char of variable upper case works only with a-z
#because in bash bellow version 4.0 is not supported expresion like upper=${word^}
function upper {
	local foo="$1"
	#result=$2
	local fz="${foo:0:1}"
	if [[ ${fz} == [a-z] ]]; then
		local ord=$(printf '%o' "'${fz}")
		local ordSmall=$(printf '%o' "'a")
		local ordBig=$(printf '%o' "'A")
		local drift=$(( ordBig - ordSmall ))
		if [ $drift -lt 0 ]; then
			local drift=$(( 0 - drift ))
		fi
		local ord=$(( ord - drift ))
		local ch=$(printf '\'${ord})
	else 
		local ch=$fz
	fi
	#eval $result="'${ch}${foo:1}'"
	echo "$ch${foo:1}"
}

function askDir {
	local __result="$1"			#first parametr is readed Value and will be returned
	if [ $# == 3 ]; then
		local question=$(printn "$2 ")$(prints "[")$(printps "$3")$(prints "] ")
	else
		local question=$(printn "$2")
	fi

	echo -n $question
	local directory
	read directory
	if [ "ahoj" == "ahoj$directory" ]; then
		local directory=$3
	fi

	eval $__result="'${directory}'"
}


#2 parameters only ask for number 
#3 args ask for number and offer default value
#4 args ask for number and check limits 2-lower limit 3-upper limit
#5 args ask for number check limits and offer default value
function askNumber {
	local __result="$1"			#first parametr is readed Value and will be returned
	local question="$(printn "$2")"
	local say="no"		#define that no default value is passed
	local limits="no"
	case $# in
		"3" ) local def=$3
			local say="$(prints "$3")"
			local question="$question$(prints "[")$(printps "$3")$(prints "]")"
			;;
		"4" ) local limitl=$3
			local limith=$4
			local limits="yes"
			;;
		"5" ) local def=$5
			local limitl=$3
			local limith=$4
			local limits="yes"
			local say="$(prints "$5")"
			local question="$question$(prints "[")$(printps "$5")$(prints "]")"
			;;
	esac


	while true; do
		echo -n "$question "
		echo -n $(prints "")
		read value
		echo -n $(printn "")
		if [ "$say" != "no" ]; then
			if [ "nula$value" == "nula" ]; then
				value=$def
			fi
		fi

		#check for value is number, else redirect error to dev null
		if [ "$value" -eq "$value" ] 2>/dev/null; then
			if [ "$limits" == "yes" ]; then
				if [ $value -ge $limitl ]; then
					if [ $limith -ge $value ]; then	#limits check passed
						eval $__result="'${value}'"
						return 0
					else
						local sayh="Please input number equal or lower than "
						echo "$(printz "$sayh")$(printp "$limith")$(printn ".")"
					fi
				else
					local sayh="Please input number equal or greater than "
					echo "$(printz "$sayh")$(printp "$limitl")$(printn ".")"
				fi
			else
				#echo $(prints "$value")	#already visible when inputing by read
				eval $__result="'${value}'"
				return 0
			fi
		else
			echo "$(printz "Please, try input a number again.")$(printn "")"
		fi
	done
	return 0
}

function ask2 {
	local var1=$2
	local var1=$(upper "$var1")
	local key1=${var1::1}
	local var2=$3
	local var2=$(upper "$var2")
	local key2=${var2::1}
    if [ $# -eq 4 ]; then
		local def=$4
		local def=${def::1}
		local def=$(upper "$def")
		if [ "$def" == "$key1" ]; then
			local say="$(prints "$var1")"
			local def=0
			local question="$(printn "$1 (")$(prints "[")$(printps "$var1")$(prints "]")$(printn "/")$(printp "$var2")$(printn ") ")"
		else
			local say="$(prints "$var2")"
			local def=1
			local question="$(printn "$1 (")$(printp "$var1")$(printn "/")$(prints "[")$(printps "$var2")$(prints "]")$(printn ") ")"
		fi
		local sayhelp="$(printz "Please press ")$(printp "ENTER")$(printz " for answering '")$(printp "$say")$(printz "' or answer by pressing '")$(printp "$key1")$(printz "' or '")$(printp "$key2")$(printz "'.")"

	else
		local say=69
		local sayhelp="$(printz "Please answer '")$(printp "$key1")$(printz "' or '")$(printp "$key2")$(printz "'.")"
		local question="$(printn "$1 (")$(printp "$var1")$(printn "/")$(printp "$var2")$(printn ") ")"
	fi

    while true; do
		echo -n  "$question "
        read -s -n1 key
		local key=$(upper $key)
        case $key in
            "$key1" ) echo $(prints "$var1")$(printn ""); return 0;;
            "$key2" ) echo $(prints "$var2")$(printn ""); return 1;;
            "") if [ "$say" != "69" ]; then
                    echo $say$(printn "")
					return $def
				else
					echo
					echo "$sayhelp"
                fi
                ;;
            *)
				echo
                echo "$sayhelp"
            ;;
        esac
    done
}


function replaceAtByWhere {
	local atLine=$1
	local by=$2
	local where=$3

	local escby=$(echo $by|sed -e 's/[]\/$*.^|[]/\\&/g')
	local args="$atLine"s/.*/$escby/

	sed -i "$args" $where
}

function searchforLineAfterWhatWhere {
	local _lineN="$1"
	local after=$2
	local what=$3
	local where=$4

	local pos=$(( $after + 1 ))
	local args="$pos,\$p"
	
	local lineN=$(sed -n -e "$args" $where|grep -n "^$what\s*="|head -n1|cut -d ':' -f1)

	if [ "nic$lineN" == "nic" ]; then
		eval $_lineN="'0'"
		return 1
	else
		local lineN=$(( $lineN + $after ))
		eval $_lineN="'${lineN}'"
	fi
}
function searchforSectionAfterWhatWhere {
	local _lineN="$1"
	local after=$2
	local what=$3
	local where=$4
	local pos=$(( $after + 1 ))
	local args="$pos,\$p"

	local lineN=$(sed -n -e "$args" $where|grep -n "^$what"|head -n1|cut -d ':' -f1)

	if [ "nic$lineN" == "nic" ]; then
		eval $_lineN="'0'"
		return 1
	else
		local lineN=$(( $lineN + $after ))
		eval $_lineN="'${lineN}'"
	fi
}

function addAfterWhatWhere {
	_after=$1
	_what=$2
	_where=$3
	_num=1

	mv $_where $_where.orig
	oIFS="$IFS"

	while IFS='' read _line; do
		if [ $_num -eq $_after ]; then
			echo "$_line"
			echo $_what
		else
			echo "$_line"
		fi
		_num=$(( $_num + 1 ))
	done  < $_where.orig > $_where
	IFS=$oIFS

	rm $_where.orig
}


function replaceSipPorts {
	local ports=$1
	local where=$2

	local atLine=0
	local new=0

	for port in $ports; do
		if searchforLineAfterWhatWhere new $atLine "sipport" "$where"; then
			local atLine=$new
			replaceAtByWhere $atLine "sipport = $port" "$where"
		else
			if [ "nic$atLine" == "nic0" ]; then
				if searchforLineAfterWhatWhere atLine 0 "#sipport" "$where"; then
					addAfterWhatWhere $atLine "sipport = $port" "$where"
					local atLine=$(( $atLine + 1 ))
				else
					if searchforSectionAfterWhatWhere atLine 0 "\[general\]" "$where"; then
						addAfterWhatWhere $atLine "sipport = $port" "$where"
						local atLine=$(( $atLine + 1 ))
					else
						echo "Section [general] not found in $where"
						exit_command 3
					fi
				fi
			else
				addAfterWhatWhere $atLine "sipport = $port" "$where"
				local atLine=$(( $atLine + 1 ))
			fi
		fi
	done
}

function replaceArgByWhere {
	local arg=$1
	local by=$2
	local where=$3
	
	local atLine=0
	local new=0

	if searchforLineAfterWhatWhere new $atLine "$arg" "$where"; then
		local atLine=$new
		replaceAtByWhere $atLine "$by" "$where"
		
	else
		if searchforLineAfterWhatWhere atLine 0 "#$arg" "$where"; then
			addAfterWhatWhere $atLine "$by" "$where"
		else
			if searchforSectionAfterWhatWhere atLine 0 "\[general\]" "$where"; then
				addAfterWhatWhere $atLine "$by" "$where"
			else
				echo "ERROR Section [general] not found in $where"
				exit_command 3
			fi
		fi
	fi
}

function readLineAtWhere {
	local _line=$1
	local num=$2
	local where=$3
	local line=$(sed -n "$num{p}" $where)

	eval $_line="'${line}'"
}

function commentoutArg {
	local what=$1
	local where=$2

	local new=0

	while true; do
		if searchforSectionAfterWhatWhere new $new "$what" "$where"; then
			readLineAtWhere line $new "$where"
			local changed=#$line
			replaceAtByWhere $new "$changed" "$where"
		else
			break
		fi
	done
}

function trim {
	local _what="$1"
	echo $(echo $_what|sed -e 's/^ *//' -e 's/ *$//')
}

#setting CTRL+C command
trap 'trap_command' SIGINT

#load functions library
##script_dir="$(dirname "$0")"
##source "$script_dir/install_prompt.lib.sh"

#0-a Check for tput command and enable / disable colors. __COLORS=1 / __COLORS=0
checkTput

#0. Say hello and check wget is installed
welcome
checkWget

#0a Check version of already installed voipmonitor
if checkVoipmonitor oldVersion; then
	echo "$(printn "You have already installed voipmonitor version $(printp "$oldVersion")$(printn ".")")"
	installedVoipmonitor=1	
	#oldVersion="0.0.0"	
else
	installedVoipmonitor=0
	oldVersion="0.0.0"
fi

#0b Check bit size and ask Customer only if not probed
checkBitSize install64bit
echo

#check for version to download and if is new available. else If no new version or version not recognized
if getVoipmonitorDownloadableVersion newLink newVersion fileName $oldVersion $install64bit; then
	echo
	if ask2 "Would you like to install newest version ($(printp "$newVersion")$(printn ") of voipmonitor sniffer?") " "yes" "no" "yes"; then 
		installVoipmonitor=1
		echo
	else
		echo "$(printn "You selected not to install newest version. Ending.")"
		echo
		trap_command
	fi
else
	echo
	if ask2 "Would you like to reinstall your current installation?" "yes" "no" "no"; then 
		installVoipmonitor=1
		echo
	else
		echo
		echo "$(printn "No new version of voipmonitor were made. Please, ")$(printp "try again")$(printn " later.")"
		echo 
		trap_command
	fi
fi

createTempDir tempDir
echo

downloadFromLink $newLink $tempDir/$fileName
echo

echo 
echo "$(printps "Now")$(printn " proceed to ")$(printp "set few options")$(printn " in configuration file.")"
echo

#1. Ask for cloud token
askToken vmToken $cloudToken
echo "Inserted token $vmToken"
echo

#1. Probe & Ask for interfaces
getNetInterfaces ifaces
checkNetInterfaces ifacesup ifacesdown $ifaces
askIfaces choosen "$ifacesup" "$ifacesdown"
introvert ifacesResult "$choosen"
echo

#2. Ask for ports
askPorts choosen
introvert portsResult "$choosen"
echo

#3. Ask for ringbuffer size
askNumber ringbufferResult "Please, insert ringbuffer size in MB " 1 2000 200
echo

#4. Ask for heap buffer size
askNumber heapbufferResult "Please, insert heap buffer size in MB " 10 10000 500
echo

#5. Storing SIP signalization (default yes)?
#sipResult=ask2 "Would you like to save SIP signalization for every call?" "yes" "no"
if ask2 "Would you like to save SIP signalization for every call?" "yes" "no"; then 
	sipResult=1
else 
	sipResult=0
fi

#6a. Storing RTP (no default value)
if ask2 "Would you like to save RTP signalization for every call?" "yes" "no"; then
#6b. Storing RTP Full or Headers only
	rtpResult=1
	if ask2 "  Would you like to save full RTP packet or RTP header packet?" "full" "header" "full"; then
		rtpheaderResult=0
	else
		rtpheaderResult=1
	fi
else
	rtpResult=0
	rtpheaderResult=0
fi

#7. Would you like to save .graph file for every call? (no default value)
if ask2 "Would you like to save .graph file for every call?" "yes" "no"; then
	graphResult=1
else
	graphResult=0
fi

#8a. You set to storing RTP would you like to compress it using LZO?
if [ $rtpResult -eq 1 ]; then
	if ask2 "Would you like to compress RTP using LZO? (LZO is very fast, but for decompression you will need voipmonitor)" "yes" "no" "yes"; then
		rtpLZO="lzo"
	else
		rtpLZO="no"
	fi
fi

#8b. Would you like to compress pcap files? dafault value yes
if ask2 "Would you like to compress pcap files?" "yes" "no" "yes"; then
#8c. Ask for compression level 
	askNumber ratioResult "  Choose ziplevel (1 is the fastest, 9 is the slowest)" 1 9 6
	zipResult=1
else
	zipResult=0
	#ratioResult=6
fi
echo

#9a. if storing of graph rtp or sip results is enabled, where to store?
storingResult=$((rtpResult + graphResult + sipResult))
if [ $storingResult -gt 0 ]; then
	askDir spooldirResult "Where you want to store spool pcap files " "/var/spool/voipmonitor"
#9b. Autocleaning of spool directory, no default value
	if ask2 "Would you like to enable autocleaning of the spool directory" "yes" "no"; then
		cleaningResult="1"
#9ba spool size
		askNumber spoolsizeResult "  Maximum size of spool directory (GB)" 1 100000 100
		if [ $sipResult -eq 1 ]; then
#9bb days for SIP pcap files [0 for disable]
		askNumber sipdaysResult "  Maximum days for SIP pcap files ( 0 for disabled ) " 0 36500 0
		fi
		if [ $rtpResult -eq 1 ]; then
#9bc days for RTP pcap files [0 for disable]
		askNumber rtpdaysResult "  Maximum days for RTP pcap files ( 0 for disabled ) " 0 36500 0
		fi
		if [ $graphResult -eq 1 ]; then
#9bd days for .graph files [0 for disable]
		askNumber graphdaysResult "  Maximum days for .graph files ( 0 for disabled ) " 0 36500 0
		fi
	else
		cleaningResult="0"
	fi
	echo
else
	spooldirResult=/var/spool/voipmonitor
fi

#10. Absolute call timeout in seconds default [14400]
askNumber timeoutResult "Absolute call timeout in seconds " 1 8640000 14400

echo
#11. Would you like to install init start script? and kill running voipmotnitor? Also show where are configs located
installFromFile configFile oldConfigFile $tempDir/$fileName $tempDir

echo
#12. Would you like to run sniffer now?
if ask2 "Would you like to run sniffer now?" "yes" "no"; then
	startResult=1
else
	startResult=0
fi

echo
echo $(printn "")
###
### end of prompting now doing
###



###
### at first disable CTLRL+C not interrupt during voipmonitor.conf updating
##trap "" SIGINT


verbose "Results:"
verbose "installedVoipmonitor=$installedVoipmonitor"
verbose
verbose "installVoipmonitor = $installVoipmonitor"
verbose "installFilename = $fileName"

verbose "cloudToken = $vmToken"

verbose "interface = ifacesResult: $ifacesResult"
replaceArgByWhere "interface" "interface = $(echo "$(trim "$ifacesResult")"|tr ' ' ',')" "$configFile"

verbose "sipport = (one per line) portsResult: $portsResult"
replaceSipPorts "$portsResult" "$configFile"

verbose "ringbuffer = ringbufferResult: $ringbufferResult"
replaceArgByWhere "ringbuffer" "ringbuffer = $ringbufferResult" "$configFile"

#verbose "packetbuffer_total_maxheap = hodnota, packetbuffer_file_path = cesta/packetbuffer, packetbuffer_enable = yes, heapbufferResult: $heapbufferResult"
verbose "max_buffer_mem, packetbuffer_file_path = filepath/packetbuffer, packetbuffer_enable = yes, heapbufferResult: $heapbufferResult"
replaceArgByWhere "packetbuffer_enable" "packetbuffer_enable = yes" "$configFile"
replaceArgByWhere "packetbuffer_file_path" "packetbuffer_file_path = /var/spool/voipmonitor/packetbuffer" "$configFile"
replaceArgByWhere "max_buffer_mem" "max_buffer_mem = $heapbufferResult" "$configFile"

verbose "storingResult: $storingResult"

verbose "savesip = yes, sipResult: $sipResult"
replaceArgByWhere "savesip" "savesip = $sipResult" "$configFile"

verbose "savertp = yes/header/no rtpResult: $rtpResult"
verbose "rtpheaderResult: $rtpheaderResult"
if [ $rtpResult -eq 1 ]; then
	if [ $rtpheaderResult -eq 1 ]; then
		replaceArgByWhere "savertp" "savertp = header" "$configFile"
	else
		replaceArgByWhere "savertp" "savertp = yes" "$configFile"
	fi
else
	replaceArgByWhere "savertp" "savertp = no" "$configFile"
fi

verbose "savegraph = plain/gzip/no graphResult: $graphResult"
if [ $graphResult -eq 1 ]; then
	replaceArgByWhere "savegraph" "savegraph = plain" "$configFile"
else
	replaceArgByWhere "savegraph" "savegraph = no" "$configFile"
fi


if [ $rtpResult -eq 1 ]; then
	verbose "pcap_dump_zip_rtp = $rtpLZO"
	replaceArgByWhere "pcap_dump_zip_rtp" "pcap_dump_zip_rtp = $rtpLZO" "$configFile"
fi

verbose "pcap_dump_zip = yes zipResult: $zipResult"
verbose "pcap_dump_ziplevel = , ratioResult: $ratioResult"
if [ $zipResult -eq 1 ]; then
	replaceArgByWhere "pcap_dump_zip" "pcap_dump_zip = yes" "$configFile"
	replaceArgByWhere "pcap_dump_ziplevel" "pcap_dump_ziplevel = $ratioResult" "$configFile"
else
	replaceArgByWhere "pcap_dump_zip" "pcap_dump_zip = no" "$configFile"
fi

verbose "cleaningResult: $cleaningResult"
verbose "spooldirResult: $spooldirResult"
replaceArgByWhere "spooldir" "spooldir = $spooldirResult" "$configFile"

if [ "yes$cleaningResult" == "yes1" ]; then
	spoolsizeResultMB=$(($spoolsizeResult * 1024))
else
	spoolsizeResultMB=0
	sipdaysResult=0
	rtpdaysResult=0
	graphdaysResult=0
fi

verbose "maxpoolsize             =  GB    spoolsizeResult: $spoolsizeResult"
replaceArgByWhere "maxpoolsize" "maxpoolsize = $spoolsizeResultMB" "$configFile"

verbose "maxpoolsipdays          =	               sipdaysResult: $sipdaysResult"
replaceArgByWhere "maxpoolsipdays" "maxpoolsipdays = $sipdaysResult" "$configFile"

verbose "maxpoolrtpdays	      = rtpdaysResult: $rtpdaysResult"
replaceArgByWhere "maxpoolrtpdays" "maxpoolrtpdays = $rtpdaysResult" "$configFile"

verbose "maxpoolgraphdays        = graphdaysResult: graphdaysResult"
replaceArgByWhere "maxpoolgraphdays" "maxpoolgraphdays = $graphdaysResult" "$configFile"

verbose "absolute_timeout = timeoutResult: $timeoutResult"
replaceArgByWhere "absolute_timeout" "absolute_timeout = $timeoutResult" "$configFile"

replaceArgByWhere "cloud_url" "cloud_url = https://cloud.voipmonitor.org/reg/register.php" "$configFile"
replaceArgByWhere "cloud_token" "cloud_token = $vmToken" "$configFile"


verbose "initResult: $initResult"
verbose "startResult: $startResult"

verbose "Commenting db params out of the configuration file :"

commentoutArg "sqldriver" "$configFile"
commentoutArg "mysqlhost" "$configFile"
commentoutArg "mysqlport" "$configFile"
commentoutArg "mysqlusername" "$configFile"
commentoutArg "mysqlpassword" "$configFile"
commentoutArg "mysqldb" "$configFile"
commentoutArg "cdr_partition" "$configFile"
commentoutArg "mysqlcompress" "$configFile"
commentoutArg "mysqlloadconfig" "$configFile"
commentoutArg "sqlcallend" "$configFile"

cmd mv "$configFile" "/etc/voipmonitor.conf"
configFile=/etc/voipmonitor.conf

removeDir $tempDir
if [ $startResult -eq 1 ]; then
	/etc/init.d/voipmonitor start
fi

###
### at end enable CTLRL+C default handling
trap - SIGINT

exit_command 0
#never reach
exit 0

