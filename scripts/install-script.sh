#!/bin/bash

echo "Copying usr/local/sbin/voipmonitor to /usr/local/sbin/voipmonitor"
cp usr/local/sbin/voipmonitor /usr/local/sbin/voipmonitor

echo "Copying etc/voipmonitor.conf to /etc/voipmonitor.conf. Edit this file to your needs"
cp etc/voipmonitor.conf /etc/

echo "Copying etc/init.d/voipmonitor starting script to /etc/init.d/voipmonitor. Start voipmonitor by /etc/init.d/voipmonitor starts"
cp etc/init.d/voipmonitor /etc/init.d/

update-rc.d voipmonitor defaults &>/dev/null
chkconfig --add voipmonitor &>/dev/null
chkconfig voipmonitor on &>/dev/null

echo 
echo "----------------------------------------------------------------------------";
echo "1) Create database voipmonitor: mysqladmin create voipmonitor";
echo "2) Import database schema:      cat cdrtable.sql | mysql voipmonitor";
echo "----------------------------------------------------------------------------";
echo;

