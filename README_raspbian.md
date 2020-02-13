# Debian 8

# What is required

```
apt-get install build-essential
apt-get install unixodbc-dev libvorbis-dev libsnappy-dev libcurl4-openssl-dev libssh-dev libpng12-dev libfftw3-dev librrd-dev liblzma-dev libgoogle-perftools-dev libgcrypt11-dev libpcap-dev libicu-dev libjson-c-dev libglib2.0-dev libxml2-dev default-libmysqlclient-dev liblzo2-dev gnutls-dev
```

# What is recommmended

## For faster (*alloc) lib
`apt-get install libtcmalloc-minimal4`

## locate directory of installed shared lib:
`ldconfig -p |grep libtcmalloc_minimal`

## cd to dir listed and create link if not already there:
`ln -s libtcmalloc_minimal.so.4.2.2 libtcmalloc_minimal.so`


# Build voipmonitor

```
git clone https://github.com/voipmonitor/sniffer.git /usr/src/voipmonitor-git
cd /usr/src/voipmonitor-git
./configure
make
make install
```

# Post Build

* copy default config from /usr/src/voipmonitor-git/config/voipmonitor.conf to /etc/voipmonitor.conf
`cp /usr/src/voipmonitor-git/config/voipmonitor.conf /etc/voipmonitor.conf`

* copy init script from /usr/src/voipmonitor-git/config/init.d/voipmonitor to /etc/init.d/voipmonitor
`cp /usr/src/voipmonitor-git/config/init.d/voipmonitor /etc/init.d/voipmonitor`

in case you are using systemd for startup services follow instructions for systemd init file at begining of this how to: https://www.voipmonitor.org/doc/Centos_7

edit configuration file /etc/voipmonitor.conf and set at least (mysqlhost, mysqlport, mysqlusername, mysqlpassword)  options and auto-cleaning options (cleandatabase,maxpoolsize)


# Web interface

Go to https://www.voipmonitor.org/doc/Debian_8
and follow instructions - start with 'Installing IOncube - php loader / decryptor'


# Mysql server

If you want use mysql server on localhost, don't forget to install also mysql-server
`apt-get install mysql-server`
