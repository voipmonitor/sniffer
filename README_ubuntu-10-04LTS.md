# INSTALL libpcap.1.1.1

```
sudo apt-get install flex
sudo apt-get install bison
cd /usr/src
wget http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz
tar xzf libpcap-1.1.1.tar.gz
cd libpcap-1.1.1
./configure
make
make install
ldconfig
```

# INSTALL MySQL

`sudo apt-get install libmysqlclient15-dev`

# INSTALL VoipMonitor svn trunk version

```
sudo apt-get install subversion libvorbis-dev libpcap-dev apache2 php5-mysql php5-gd unixodbc-dev  libapache2-mod-php5
cd /usr/src
svn co https://voipmonitor.svn.sourceforge.net/svnroot/voipmonitor/trunk voipmonitor-svn
cd voipmonitor-svn
make clean
make
make install
mkdir /var/spool/voipmonitor
chown www-data /var/spool/voipmonitor
mysqladmin create voipmonitor
cat cdrtable.sql | mysql voipmonitor
```
