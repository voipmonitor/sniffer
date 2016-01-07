#!/bin/bash
echo "Installing /usr/local/share/voipmonitor/audio"
mkdir -p /usr/local/share/voipmonitor/audio
cp usr/local/share/voipmonitor/audio/* /usr/local/share/voipmonitor/audio/

echo "Installing voipmonitor binary to /usr/local/sbin/voipmonitor"
mkdir -p /usr/local/sbin
cp usr/local/sbin/voipmonitor /usr/local/sbin/voipmonitor

echo "Installing etc/voipmonitor.conf to /etc/voipmonitor.conf. Edit this file to your needs"
cp -i etc/voipmonitor.conf /etc/

echo "Installing etc/init.d/voipmonitor starting script to /etc/init.d/voipmonitor. Start voipmonitor by /etc/init.d/voipmonitor start"
cp etc/init.d/voipmonitor /etc/init.d/

echo "Creating /var/spool/voipmonitor"
mkdir /var/spool/voipmonitor


update-rc.d voipmonitor defaults &>/dev/null
chkconfig --add voipmonitor &>/dev/null
chkconfig voipmonitor on &>/dev/null

echo;
echo "Create database voipmonitor with this command: mysqladmin create voipmonitor";
echo "Edit /etc/voipmonitor.conf";
echo "Run voipmonitor /etc/init.d/voipmonitor start";
echo;

