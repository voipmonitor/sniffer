# PBX In A Flash

```
yum install  mysql-devel
wget http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz
tar zxvf libpcap-1.1.1.tar.gz
cd libpcap-1.1.1
./configure
make
make install
ldconfig
cd ..

wget http://downloads.sourceforge.net/project/voipmonitor/2.1/voipmonitor-2.1.tar.gz?r=http%3A%2F%2Fwww.voipmonitor.org%2F&ts=1299123384&use_mirror=surfnet
tar zxvf voipmonitor-2.1.tar.gz
mv voipmonitor-2.1 voipmonitor
cd voipmonitor
make
make install
mysqladmin create –u root voipmonitor –p passw0rd
cat cdrtable.sql | mysql voipmonitor –p passw0rd
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
chmod 0777 /usr/local/lib
mkdir /var/spool/voipmonitor
chmod 777 /var/spool/voipmonitor
```
run it 
`voipmonitor -i eth0 -SRG -h localhost -b voipmonitor -u root -p passw0rd`
