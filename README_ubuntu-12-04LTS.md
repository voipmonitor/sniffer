# Debian 6.0

```
apt-get install build-essential subversion libvorbis-dev libpcap-dev apache2 php5-mysql php5-gd mysql-server unixodbc-dev libapache2-mod-php5 tshark libmysqlclient-dev zlib1g-dev

cd /usr/src
svn co https://voipmonitor.svn.sourceforge.net/svnroot/voipmonitor/trunk  voipmonitor-svn
cd voipmonitor-svn
./configure
make clean
make
make install
mkdir /var/spool/voipmonitor
mysqladmin create voipmonitor
cat cdrtable.sql | mysql voipmonitor
cp config/voipmonitor.conf /etc/
#edit file /etc/voipmonitor.conf to your needs
cp config/init.d/voipmonitor /etc/init.d/
update-rc.d voipmonitor defaults
/etc/init.d/voipmonitor start
```
