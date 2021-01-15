#ifndef CALLTABLE_BASE_H
#define CALLTABLE_BASE_H


struct s_sdp_flags_base {
	s_sdp_flags_base() {
		is_fax = 0;
		is_video = 0;
		rtcp_mux = 0;
	}
	s_sdp_flags_base(bool is_fax, bool is_video, bool rtcp_mux) {
		this->is_fax = is_fax;
		this->is_video = is_video;
		this->rtcp_mux = rtcp_mux;
	}
	inline int operator != (const s_sdp_flags_base &other) {
		return(is_fax != other.is_fax ||
		       is_video != other.is_video ||
		       rtcp_mux != other.rtcp_mux);
	}
	int8_t is_fax : 1;
	int8_t is_video : 1;
	int8_t rtcp_mux : 1;
};


#endif
