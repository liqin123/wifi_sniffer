#define LT_BITFIELD8        uint8_t
#define LT_BITFIELD16       uint16_t
#define LT_BITFIELD32       uint32_t
#define LT_BITFIELD64       uint64_t


#define __BYTE_ORDER 0
#define __LITTLE_ENDIAN 1
#define __BIG_ENDIAN 0

#  define PACKED __attribute__((packed))


/** Generic LLC/SNAP header structure */
typedef struct libtrace_llcsnap
{
/* LLC */
  uint8_t dsap;			/**< Destination Service Access Point */
  uint8_t ssap;			/**< Source Service Access Point */
  uint8_t control;		/**< Control field */
/* SNAP */
  LT_BITFIELD32 oui:24;		/**< Organisationally Unique Identifier (scope)*/
  uint16_t type;		/**< Protocol within OUI */
} PACKED libtrace_llcsnap_t;



typedef struct ieee80211_frame_control {
# if __BYTE_ORDER == __LITTLE_ENDIAN	
	uint8_t		version:2;
	uint8_t		type:2;
	uint8_t		subtype:4;
	uint8_t		to_ds:1;
	uint8_t		from_ds:1;
	uint8_t		more_frag:1;
        uint8_t		retry:1;
        uint8_t		power:1;
        uint8_t		more_data:1;
        uint8_t		wep:1;
        uint8_t		order:1;
# elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		subtype:4;
	uint8_t		type:2;
	uint8_t		version:2;
        uint8_t		order:1;
        uint8_t		wep:1;
        uint8_t		more_data:1;
        uint8_t		power:1;
        uint8_t		retry:1;
	uint8_t		more_frag:1;
	uint8_t		from_ds:1;
	uint8_t		to_ds:1;
#else
#	error "Adjust your <bits/endian.h> defines"
# endif	
} __attribute__ ((__packed__)) ieee80211_frame_control;

typedef struct ieee80211_ctrl_frame_1addr {
	ieee80211_frame_control	ctl;
        uint16_t     duration;
        uint8_t      addr1[6];
} __attribute__ ((__packed__)) ieee80211_ctrl_frame_1addr;

typedef struct ieee80211_ctrl_frame_2addr {
	ieee80211_frame_control	ctl;
        uint16_t     duration;
        uint8_t      addr1[6];
        uint8_t      addr2[6];
} __attribute__ ((__packed__)) ieee80211_ctrl_frame_2addr;

typedef struct ieee80211_data_frame_3 {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
} __attribute__ ((__packed__)) ieee80211_data_frame_3;

typedef struct ieee80211_data_frame {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
	uint8_t		addr4[6];
} __attribute__ ((__packed__)) ieee80211_data_frame;

typedef struct ieee80211_qos_data_frame {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
	uint8_t		addr4[6];
	uint16_t	qos;
} __attribute__ ((__packed__)) ieee80211_qos_data_frame;

typedef struct ieee80211_mgmt_frame {
	ieee80211_frame_control ctl;
	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];
	uint16_t	seq_ctrl;
} __attribute__ ((__packed__)) ieee80211_mgmt_frame;

typedef struct ieee80211_payload {
	uint16_t	ethertype;
	uint8_t		payload[1];
} __attribute__ ((__packed__)) ieee80211_payload;



typedef struct ieee80211_capinfo 
{
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	uint8_t	ess:1;
	uint8_t	ibss:1;
	uint8_t	cf_pollable:1;
	uint8_t	cf_poll_req:1;
	uint8_t	privacy:1;
	uint8_t	short_preamble:1;
	uint8_t	pbcc:1;
	uint8_t	channel_agility:1;
	uint8_t	spectrum_mgmt:1;
	uint8_t	qos:1;
	uint8_t	short_slot_time:1;
	uint8_t	apsd:1;
	uint8_t	res1:1;
	uint8_t	dsss_ofdm:1;
	uint8_t	delayed_block_ack:1;
	uint8_t	immediate_block_ack:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t	channel_agility:1;
	uint8_t	pbcc:1;
	uint8_t	short_preamble:1;
	uint8_t	privacy:1;
	uint8_t	cf_poll_req:1;
	uint8_t	cf_pollable:1;
	uint8_t	ibss:1;
	uint8_t	ess:1;
	uint8_t	immediate_block_ack:1;
	uint8_t	delayed_block_ack:1;
	uint8_t	dsss_ofdm:1;
	uint8_t	res1:1;
	uint8_t	apsd:1;
	uint8_t	short_slot_time:1;
	uint8_t	qos:1;
	uint8_t	spectrum_mgmt:1;
#else
# error "Unknown byte order -- please check <bits/endian.h>"
#endif
} __attribute__ ((__packed__)) ieee80211_capinfo;

typedef struct ieee80211_beacon 
{
	ieee80211_mgmt_frame mgmt;
	uint64_t	ts;
	uint16_t	interval;
	ieee80211_capinfo capinfo;
} __attribute__ ((__packed__)) ieee80211_beacon;

typedef struct ieee80211_assoc_req { 
	ieee80211_mgmt_frame mgmt;
	ieee80211_capinfo capinfo;
	uint16_t	listen_interval;
} __attribute__ ((__packed__)) ieee80211_assoc_req;

typedef struct ieee80211_assoc_resp {
	ieee80211_mgmt_frame mgmt;
	ieee80211_capinfo capinfo;
	uint16_t	status_code;
	uint16_t	assoc_id;
} __attribute__ ((__packed__)) ieee80211_assoc_resp;

typedef struct ieee80211_reassoc_req {
	ieee80211_mgmt_frame mgmt;
	ieee80211_capinfo capinfo;
	uint16_t	listen_interval;
	uint8_t		current_address[6];
} __attribute__ ((__packed__)) ieee80211_reassoc_req;

typedef struct ieee80211_auth {
	ieee80211_mgmt_frame mgmt;
	uint16_t	auth_algo_num;
	uint16_t	auth_trans_seq_num;
	uint16_t	status_code;
} __attribute__ ((__packed__)) ieee80211_auth;


typedef struct ieee80211_ie {
	uint8_t		id;
	uint8_t		length;
} __attribute__ ((__packed__)) ieee80211_ie;


void decode_80211_vendor_ie(ieee80211_ie *ie) ;
void decode_80211_information_elements(const char *pkt, unsigned len) ;
void ieee80211_print_reason_code(uint16_t code) ;
void ieee80211_print_status_code(uint16_t code) ;
void decode_80211_capinfo(ieee80211_capinfo *c) ;
void decode_80211_beacon(const char *pkt, unsigned len) ;
void decode_80211_assoc_request(const char *pkt, unsigned len) ;
void decode_80211_assoc_response(const char *pkt, unsigned len) ;
void decode_80211_reassoc_request(const char *pkt, unsigned len) ;
void decode_80211_authentication_frame(const char *pkt, unsigned len) ;
void decode_80211_mgmt(const char *pkt, unsigned len) ;
void decode_80211_ctrl(const char *pkt, unsigned len) ;
void decode_80211_data(const char *pkt, unsigned len) ;
void decode(const char *pkt, unsigned len) ;
