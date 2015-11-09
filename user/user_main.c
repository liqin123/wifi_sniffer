#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "mem.h"
#include "user_config.h"
#include "user_interface.h"
#include "driver/uart.h"
//#include "80211hdr.h"
#include "80211_mgt.h"
#include "80211decode.h"

#define user_procTaskPrio		0
#define user_procTaskQueueLen	1
os_event_t	user_procTaskQueue[user_procTaskQueueLen];
static volatile os_timer_t deauth_timer;

// Channel to perform deauth
uint8_t channel = 1;




// Sequence number of a packet from AP to client
uint16_t seq_n = 0;

// Packet buffer
uint8_t packet_buffer[64];

/* ==============================================
 * Promiscous callback structures, see ESP manual
 * ============================================== */
 
struct RxControl {
	signed rssi:8;
	unsigned rate:4;
	unsigned is_group:1;
	unsigned:1;
	unsigned sig_mode:2;
	unsigned legacy_length:12;
	unsigned damatch0:1;
	unsigned damatch1:1;
	unsigned bssidmatch0:1;
	unsigned bssidmatch1:1;
	unsigned MCS:7;
	unsigned CWB:1;
	unsigned HT_length:16;
	unsigned Smoothing:1;
	unsigned Not_Sounding:1;
	unsigned:1;
	unsigned Aggregation:1;
	unsigned STBC:2;
	unsigned FEC_CODING:1;
	unsigned SGI:1;
	unsigned rxend_state:8;
	unsigned ampdu_cnt:8;
	unsigned channel:4;
	unsigned:12;
};
 
struct LenSeq {
	uint16_t length;
	uint16_t seq;
	uint8_t  address3[6];
};

struct sniffer_buf {
	struct RxControl rx_ctrl;
	uint8_t buf[36];
	uint16_t cnt;
	struct LenSeq lenseq[1];
};

struct sniffer_buf2{
	struct RxControl rx_ctrl;
	uint8_t buf[112];
	uint16_t cnt;
	uint16_t len;
};

struct RxPacket 
{
	struct RxControl rx_ctl;
	uint8 data[];
};


/* Listens communication between AP and client */
static void ICACHE_FLASH_ATTR
promisc_cb(uint8_t *buf, uint16_t len)
{
	//os_printf("---------------\n");
	//os_printf("promisc_cb len:%d\n", len -12);
	//os_printf("---------------\n");
/*
	if (len == 50)
	{
		decode(&buf[12], 200);
	}
	*/
	
	struct RxPacket * pkt = (struct RxPacket*) buf;
	if (len > 12 && len < 128)
	{
		os_printf("legacy_length: %d\n", pkt->rx_ctl.legacy_length);
		//hex_print((char *)pkt, len);


        hex_print((char *)pkt, pkt->rx_ctl.legacy_length + 12);

		decode((char *)&pkt->data, pkt->rx_ctl.legacy_length);
	}
	//os_printf("promisc_cb\tLen:%d\n", len);
	/*
	if (len == 12)
	{
		struct RxControl *sniffer = (struct RxControl*) buf;
	} else if (len == 128) 
	{
		struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
	} else 
	{
		struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;

		//decode_probe_req((PFRAME)sniffer->buf);
		//decode_test(sniffer->buf);
		//decode(sniffer->buf, len-12);
		//decode(sniffer->buf, sniffer->);
	}
	*/
}

void ICACHE_FLASH_ATTR
sniffer_system_init_done(void)
{
	// Set up promiscuous callback
 //   wifi_set_channel(1);
 //   wifi_set_channel(6);
	wifi_set_channel(1);
	//wifi_promiscuous_enable(0);
	wifi_set_promiscuous_rx_cb(promisc_cb);
	wifi_promiscuous_enable(1);
}

void ICACHE_FLASH_ATTR
user_init()
{
	uart_init(115200, 115200);
	os_printf("\n\nSDK version:%s\n", system_get_sdk_version());
	
	// Promiscuous works only with station mode
	wifi_set_opmode(STATION_MODE);
	
	// Set timer for deauth
	//os_timer_disarm(&deauth_timer);
	//os_timer_setfn(&deauth_timer, (os_timer_func_t *) deauth, NULL);
	//os_timer_arm(&deauth_timer, CHANNEL_HOP_INTERVAL, 1);
	
	// Continue to 'sniffer_system_init_done'
	system_init_done_cb(sniffer_system_init_done);
}
