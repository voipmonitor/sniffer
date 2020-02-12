# Install voipmonitor dependencies

`emerge libpcap zlib`

# Install voipmonitor

```
cd /path/to/voipmonitor
make clean
make
make install
cp config/voipmonitor.conf /etc/
cp config/init.d/voipmonitor /etc/init.d/

Edit the config file, prepare the mysql table and run voipmonitor
```

## Install voipmonitor

```
cd /path/to/voipmonitor
make
make install
cp config/voipmonitor.conf /etc/
cp config/init.d/voipmonitor /etc/init.d/
```

Edit the config file, prepare the mysql table and run voipmonitor

