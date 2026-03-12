#ifndef RTCP_H
#define RTCP_H


#include <map>
#include <queue>


void parse_rtcp(char *data, int datalen, timeval *ts, CallBranch *c_branch,
		vmIP ip_src, vmPort port_src, vmIP ip_dst, vmPort port_dst, bool srtcp = false);

class cRtcpRtd {
public: 
	enum eRtdTypeCalc {
		_rtd_tc_rfc         = 1,
		_rtd_tc_ws          = 2,
		_rtd_tc_ws_bug      = 4,
		_rtd_tc_use_last_sr = 8
	};
private:
	struct sRtcpRtd_SendDesc_key {
		u_int32_t ssrc;
		u_int32_t ntp_ts;
		inline bool operator == (const sRtcpRtd_SendDesc_key& other) const {
			return(this->ssrc == other.ssrc &&
			       this->ntp_ts == other.ntp_ts);
		}
		inline bool operator < (const sRtcpRtd_SendDesc_key& other) const {
			return(this->ssrc < other.ssrc ? 1 : this->ssrc > other.ssrc ? 0 :
			       this->ntp_ts < other.ntp_ts);
		}
	};
	struct sRtcpRtd_SendDesc : public sRtcpRtd_SendDesc_key {
		u_int64_t pkt_ts;
	};
	struct sRtcpRtd_Report {
		u_int32_t ssrc;
		u_int32_t last_sr_ts;
		u_int32_t delay;
	};
	struct sRtcpRtd_Rec {
		sRtcpRtd_SendDesc send_desc;
		map<u_int32_t, sRtcpRtd_Report> reports;
	};
public:
	cRtcpRtd();
	~cRtcpRtd();
	void newSendDesc(struct rtcp_sr_senderinfo *senderinfo, struct timeval *pkt_ts);
	void addReportBlock(struct rtcp_sr_senderinfo *senderinfo, struct rtcp_sr_reportblock *reportblock);
	int getRtd(u_int32_t reporter_ssrc, u_int32_t cur_sr_ts, struct rtcp_sr_reportblock *reportblock, struct timeval *pkt_ts, int rtd_type_calc);
private:
	u_int16_t queue_limit;
	map<sRtcpRtd_SendDesc_key, sRtcpRtd_Rec*> map_recs;
	map<u_int32_t, sRtcpRtd_Rec*> map_last_by_ssrc;
	queue<sRtcpRtd_Rec*> queue_recs;
};


#endif
