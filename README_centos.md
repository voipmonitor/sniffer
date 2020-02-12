# What is required

- C and C++ compiler (gcc,g++)
- libpcap-dev package >= 1.0
- zlib ibrary 
- snappy library
- Libogg, Libvorbis 
- unixODBC-devel

- Make sure mysql is installed when building CentOS
- Under the Web Server include the mysql-devel and php-mysql packages

# Pre-Build

yum groupinstall 'Development Tools'
yum install subversion unixODBC-devel mysql-devel libogg libogg-devel vorbis-tools libvorbis libvorbis-devel libpcap-devel zlib-devel

for CentOS >= 7.4:

yum install libicu-devel snappy-devel libcurl-devel libssh-devel libpng-devel fftw-devel openssl-devel json-c-devel rrdtool-devel glib2-devel libxml2-devel lzo-devel gnutls-devel libgcrypt-devel gperftools-devel

# Snappy library

wget https://snappy.googlecode.com/files/snappy-1.1.0.tar.gz
tar xzf snappy-1.1.0.tar.gz
cd snappy-1.1.0
./configure
make
make install

## (for older centos < 6.3) 

wget http://www.tcpdump.org/release/libpcap-1.3.0.tar.gz
tar xzf libpcap-1.1.1.tar.gz
cd libpcap*
./configure
make
make install

# Build voipmonitor

svn co http://svn.code.sf.net/p/voipmonitor/code/trunk voipmonitor-svn
cd voipmonitor-svn
rm Makefile
./configure
make
make install
mkdir /var/spool/voipmonitor
chown apache /var/spool/voipmonitor

# Post Build

## Start mysql

yum install mysql-server
chkconfig mysqld on
service mysqld start
cp config/voipmonitor.conf /etc/
#edit file /etc/voipmonitor.conf to your needs
cp config/init.d/voipmonitor /etc/init.d/
chkconfig --add voipmonitor
chkconfig voipmonitor on

# Web Interface

## Enable Apache

yum install httpd php php-gd php-mysql php-process
chkconfig httpd on
service httpd start

## Install the voipmonitor Interface

go to voipmonitor.org/download and download manual and GUI

