# What is VoIPmonitor

VoIPmonitor is open source live network packet sniffer which analyze SIP 
and RTP protocol. It can run as daemon or analyzes already captured pcap 
files. For each detected VoIP call voipmonitor calculates statistics about 
loss, burstiness, latency and predicts MOS (Meaning Opinion Score) according 
to ITU-T G.107 E-model. These statistics are saved to MySQL database and each 
call is saved as pcap dump. Web PHP application (it is not part of open 
source sniffer) filters data from database and graphs latency and loss 
distribution. Voipmonitor also detects improperly terminated calls when 
BYE or OK was not seen. To accuratly transform latency to loss packets, 
voipmonitor simulates fixed and adaptive jitterbuffer.


## Key features

- Fast C++ SIP/RTP packet analyzer
- Predicts MOS-LQE score according to ITU-T G.107 E-model
- Detailed delay/loss statistics stored to MySQL
- Each call is saved as standalone pcap file
- Call recorder

## Sponsors and contributors

- Telephonic http://telephonic.ca
* init script, configuration file

## Installation

Check README_*.md






















.
