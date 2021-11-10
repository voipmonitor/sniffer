#ifndef CALLTABLE_BASE_H
#define CALLTABLE_BASE_H


enum e_sdp_media_type {
	sdp_media_type_na,
	sdp_media_type_audio = (1<<0),
	sdp_media_type_image = (1<<1),
	sdp_media_type_video = (1<<2),
	sdp_media_type_application = (1<<3)
};

struct s_sdp_flags_base {
	s_sdp_flags_base() {
		media_type = sdp_media_type_na;
		rtcp_mux = false;
	}
	s_sdp_flags_base(e_sdp_media_type media_type, bool rtcp_mux) {
		this->media_type = media_type;
		this->rtcp_mux = rtcp_mux;
	}
	inline int operator != (const s_sdp_flags_base &other) {
		return(media_type != other.media_type ||
		       rtcp_mux != other.rtcp_mux);
	}
	inline bool is_audio() {
		return(media_type & sdp_media_type_audio);
	}
	inline bool is_image() {
		return(media_type & sdp_media_type_image);
	}
	inline bool is_video() {
		return(media_type & sdp_media_type_video);
	}
	inline bool is_application() {
		return(media_type & sdp_media_type_application);
	}
	u_int8_t media_type : 4;
	u_int8_t rtcp_mux : 1;
};


#endif
