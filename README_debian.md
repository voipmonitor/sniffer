# Debian

`apt-get install build-essential git libmysqlclient-dev libvorbis-dev libpcap-dev unixodbc-dev libsnappy-dev libcurl4-openssl-dev libssh-dev libjson0-dev librrd-dev liblzo2-dev liblzma-dev libglib2.0-dev libxml2-dev`

## optional packages
`apt-get install libpng-dev libgcrypt-dev libfftw3-dev libgoogle-perftools-dev gnutls-dev`

```
cd /usr/src
git clone https://github.com/voipmonitor/sniffer.git
cd sniffer
./configure
make
```

(Is possible you will get a warning like this: " Warning: the use of `tmpnam' is dangerous, better use `mkstemp" just continue with the next command)

```
make install
cp config/voipmonitor.conf /etc/
#edit file /etc/voipmonitor.conf to your needs
cp config/init.d/voipmonitor /etc/init.d/
update-rc.d voipmonitor defaults
/etc/init.d/voipmonitor start
```
