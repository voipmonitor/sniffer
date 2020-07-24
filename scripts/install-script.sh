#!/bin/bash

SHAREDIR=usr/local/share/voipmonitor
AUDIODIR=$SHAREDIR/audio
BINDIR=usr/local/sbin
CFGDIR=etc
INITDIR=$CFGDIR/init.d
SENSOR=voipmonitor
SPOOLDIR=/var/spool/$SENSOR

if [ "a$1" == "a--uninstall" ]
then

	echo "Stopping $SENSOR"
	/$INITDIR/$SENSOR stop

	echo "Uninstalling /$SHAREDIR"
	rm -rf /$SHAREDIR

	echo "Uninstalling $SENSOR binary from /$BINDIR/$SENSOR"
	rm /$BINDIR/$SENSOR

	echo "Moving /$CFGDIR/$SENSOR.conf to /$CFGDIR/$SENSOR.conf-backup."
	mv /$CFGDIR/$SENSOR.conf /$CFGDIR/$SENSOR.conf-backup

	echo "Deleting $SPOOLDIR"
	rm -rf $SPOOLDIR

	update-rc.d $SENSOR remove &>/dev/null
	chkconfig $SENSOR off &>/dev/null
	chkconfig --del $SENSOR &>/dev/null

	echo "Deleting starting script /$INITDIR/$SENSOR"
	rm /$INITDIR/$SENSOR

	echo;
	echo "The database is not deleted. Do it manually.";
	echo;
	exit 0;
fi

if [ "a$1" == "a--no-user-input" ]
then
	NOUSERINPUT=yes
else
	NOUSERINPUT=""
fi

echo "Installing /$AUDIODIR"
mkdir -p /$AUDIODIR
cp $AUDIODIR/* /$AUDIODIR/

echo "Installing $SENSOR binary to /$BINDIR/$SENSOR"
mkdir -p /$BINDIR
cp $BINDIR/$SENSOR /$BINDIR/$SENSOR

echo "Installing $INITDIR/$SENSOR starting script to /$INITDIR/$SENSOR. Start $SENSOR by /$INITDIR/$SENSOR start"
cp $INITDIR/$SENSOR /$INITDIR/

# ask/set spool directory, usage # as a delimiter in sed
DEFSPOOLDIR=/var/spool/voipmonitor
if [ -z $NOUSERINPUT ]; then
	echo -n "Enter spool directory [$DEFSPOOLDIR]: "
	read TMPSPOOL
fi
if [ -z "$TMPSPOOL" ]; then
	SPOOLDIR=$DEFSPOOLDIR
else
	SPOOLDIR=$TMPSPOOL
fi
sed -i "s#^spooldir[\t= ]\+.*\$#spooldir = $SPOOLDIR#" $CFGDIR/$SENSOR.conf
echo "Creating $SPOOLDIR"
mkdir $SPOOLDIR

# ask/set sniffing interface(s)
DEFINT=eth0
if [ -z $NOUSERINPUT ]; then
	echo -n "Enter sniffing interface(s). More interface names must separated by comma. [$DEFINT]: "
	read TMPINT
fi
if [ -z "$TMPINT" ]; then
	INTERFACE=$DEFINT
else
	INTERFACE=$TMPINT
fi
sed -i "s#^interface[\t= ]\+.*\$#interface = $INTERFACE#" $CFGDIR/$SENSOR.conf

# ask/set maxpool size
DEFMAXPOOLSIZE=102400
if [ -z $NOUSERINPUT ]; then
	echo -n "Enter max pool size for pcaps store (in MB). [$DEFMAXPOOLSIZE]: "
	read TMPMAXPOOLSIZE
fi
if [ -z "$TMPMAXPOOLSIZE" ]; then
	MAXPOOLSIZE=$DEFMAXPOOLSIZE
else
	MAXPOOLSIZE=$TMPMAXPOOLSIZE
fi
sed -i "s#^maxpoolsize[\t= ]\+.*\$#maxpoolsize = $MAXPOOLSIZE#" $CFGDIR/$SENSOR.conf


echo "Installing $CFGDIR/$SENSOR.conf to /$CFGDIR/$SENSOR.conf. Edit this file to your needs"
if [ -z $NOUSERINPUT ]; then
	cp -i $CFGDIR/$SENSOR.conf /$CFGDIR/
else
	if [ -f /$CFGDIR/$SENSOR.conf ]; then
		echo "File /$CFGDIR/$SENSOR.conf already exists, no copying."
	else
		cp $CFGDIR/$SENSOR.conf /$CFGDIR/
	fi
fi

update-rc.d $SENSOR defaults &>/dev/null
chkconfig --add $SENSOR &>/dev/null
chkconfig $SENSOR on &>/dev/null

echo;
echo "Create database $SENSOR with this command: mysqladmin create $SENSOR";
echo "Edit /$CFGDIR/$SENSOR.conf";
echo "Run $SENSOR /$INITDIR/$SENSOR start";
echo;

