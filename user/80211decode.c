/* 
 * 802.11 libpacketdump decoder
 * 
 * Originally based on "wagdump" (c) 2005 Dean Armstrong
 *
 * This decoder will attempt to do it's best at decoding the frame formats
 * defined in the following standards. Not all fields are decoded, but they
 * are at least acknowledged as being present. 
 *
 *  802.11
 *  802.11b
 *  802.11d - operation in multiple regulatory domains
 *  802.11e - wireless multimedia extensions
 *  802.11g
 *  802.11h - power management
 *  802.11i - MAC security enhancements 
 *
 *  It will also attempt to decode vendor specific Information Elements
 *  if possible.
 *
 *  (c) 2006 Scott Raynel <scottraynel@gmail.com>
 */

#include <sys/types.h>
//#include <netinet/in.h>
#include <stdio.h>
//#include <inttypes.h>
//#include "libpacketdump.h"
#include "osapi.h"
#include "ets_sys.h"
#include "80211decode.h"

#define printf(...) os_printf( __VA_ARGS__ )
#define sprintf(...) os_sprintf( __VA_ARGS__ )



void hex_print(char *p, size_t n)
{
	char HEX[]="0123456789ABCDEF";
	unsigned int i,j,count;
	j=0;
	i=0;
	count=0;
	while(j < n)
	{
		count++;
		os_printf("0x%02x\t",count);
		if(j+16<n){
			for(i=0;i<16;i++)
			{
				os_printf("0x%c%c ",HEX[(p[j+i]&0xF0) >> 4],HEX[p[j+i]&0xF]);
			}
			os_printf("\t");
			for(i=0;i<16;i++)
			{
				os_printf("%c",isprint(p[j+i])?p[j+i]:'.');
			}
			os_printf("\n");
			j = j+16;
		}
		else
		{
			for(i=0;i<n-j;i++)
			{
				os_printf("0x%c%c ",HEX[(p[j+i]&0xF0) >> 4],HEX[p[j+i]&0xF]);
			}
			os_printf("\t");
			for(i=0;i<n-j;i++)
			{
				os_printf("%c",isprint(p[j+i])?p[j+i]:'.');
			}
			os_printf("\n");
			break;
		}
	}
}

 char *macaddr(uint8_t mac[]) 
 {
	static char ether_buf[18] = {0, };
	os_sprintf(ether_buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
	return ether_buf;
}
/*
 * Takes a vendor IE and decodes it
 */

 void decode_80211_vendor_ie(ieee80211_ie *ie) 
{
	uint8_t *data = (uint8_t *) ((char *)ie + sizeof(ieee80211_ie));
	uint32_t ie_oui;	
	os_printf("  Vendor Private Information Element\n");
	if (ie->length <= 3) return;
	ie_oui = (data[0] << 16) | (data[1] << 8) | data[2];
	switch(ie_oui) {
		case 0x0050f2:
			os_printf("   Atheros 802.11i/WPA IE\n");
			break;
		case 0x00037f:
			os_printf("   Atheros Advanced Capability IE\n");
			break;
		default:
			os_printf("   Unknown Vendor OUI (0x%06x)\n", ie_oui);
			break;
	}

}


/* 
 * Takes a pointer to the start of the IEs in a beacon and the
 * length remaining and decodes the IEs.
 */
 void decode_80211_information_elements(const char *pkt, unsigned len) 
 {
 	//os_printf("decode_80211_information_elements len:%d\n", len);
 	//os_printf("----------------------------------------------------\n");
 	//hex_print((char *)pkt, len);
 	//os_printf("----------------------------------------------------\n");

	ieee80211_ie *ie;
	int i = 0;
	const uint8_t * data;
	uint8_t bmap_offset;
	while (len >= sizeof(ieee80211_ie)) 
	{
		ie = (ieee80211_ie *) pkt;
		
		if ( len < ( sizeof(ieee80211_ie) + ie->length)) 
		{
			os_printf("  [Truncated]\n");
			return;
		}
		
		data = (( const unsigned char *)pkt + sizeof (ieee80211_ie));
		
		switch (ie->id) 
		{
			case 0:
				os_printf("  SSID = ");
				for (i = 0; i < ie->length; i++) 
					os_printf("%c", data[i]);
				os_printf("\n");
				break;
			case 1:
				os_printf("  Supported Rates (Kbit/s):\n   ");
				/* NB: the MSB of each field will be set
				 * if the rate it describes is part of the
				 * basic rate set, hence the AND */
				for (i = 0; i < ie->length; i++) {
					os_printf("%u, ", 
						( (data[i]&0x7F) * 500));

				}
				os_printf("%c%c\n", 0x8, 0x8);
				break;
			case 3:
				os_printf("  DSSS Channel = ");
				os_printf("%u\n", *data);
				break;
			case 5:
				os_printf("  Traffic Indication Message:\n");
				os_printf("   DTIM Count = %u, ", *data);
				data++;
				os_printf("DTIM Period = %u\n", *data);
				data++;
				os_printf("   Broadcast/Multicast waiting = %s\n", 
					(*data) & 0x01 ? "Yes\0" : "No\0");
				bmap_offset = ((*data) & 0xFE) >> 1;
				data++;
				if ((ie->length == 4) && ( *data == 0)) {
					os_printf("   No traffic waiting for stations\n");
					break;
				}
				
				os_printf("   Traffic waiting for AssocIDs: ");
				for (i = 0; i < (ie->length - 3); i++) {
					int j;
					for (j = 0; j < 8; j++) {
						if (data[i] & (1 << j)) {
							os_printf("%u ", (bmap_offset + i + 1) * 8 + j);
						}
					}
				}		
				os_printf("\n");
						
				break;
			case 7:
				os_printf("  802.11d Country Information:\n");
				os_printf("   ISO 3166 Country Code: %c%c\n", data[0], data[1]);
				os_printf("   Regulatory Operating Environment: ");
				if (data[2] == ' ') os_printf("Indoor/Outdoor\n");
				else if (data[2] == 'O') os_printf("Outdoor only\n");
				else if (data[2] == 'I') os_printf("Indoor only\n");
				else os_printf("Unknown, code = %c\n", data[2]);
				data += sizeof(uint8_t) * 3;
				for (i = 0; i < ((ie->length - 3) / 3); i++) {
					os_printf("   First Channel: %u, Num Channels: %u, Max Tx Power %idBm\n",
							data[0], data[1], (int8_t) data[2]);
					data += sizeof(uint8_t) * 3;
				}
				
				break;
			case 11:
				os_printf("  802.11e QBSS Load\n");
				break;
			case 12:
				os_printf("  802.11e EDCA Parameter\n");
				break;
			case 13:
				os_printf("  802.11e TSPEC\n");
				break;
			case 14:
				os_printf("  802.11e TCLAS\n");
				break;
			case 15:
				os_printf("  802.11e Schedule\n");
				break;
			case 16:
				os_printf("  Authentication Challenge Text\n");
				break;
			case 32:
				os_printf("  802.11h Power Contraint\n");
				os_printf("   Local Power Contraint = %udB\n", data[0]);
				break;
			case 33:
				os_printf("  802.11h Power Capability\n");
				os_printf("   Minimum Transmit Power Capability = %idBm\n", (int8_t)data[0]);
				os_printf("   Maximum Transmit Power Capability = %idBm\n", (int8_t)data[1]);
				break;
			case 34:
				os_printf("  802.11h Transmit Power Control Request\n");
				break;
			case 35:
				os_printf("  802.11h Transmit Power Control Report\n");
				os_printf("   Transmit Power = %idBm\n", (int8_t)data[0]);
				os_printf("   Link Margin = %idB\n", (int8_t)data[1]);
				break;
			case 36:
				os_printf("  802.11h Supported Channels\n");
				for(i = 0; i < (ie->length / 2); i++) {
					os_printf("   First Channel = %u, Num Channels = %u\n", data[0], data[1]);
					data += 2;
				}
				break;
			case 37:
				os_printf("  802.11h Channel Switch Announcement\n");
				os_printf("   New Channel Number = %u\n", data[1]);
				os_printf("   Target Beacon Transmission Times untill switch = %u\n", data[2]);
				if (data[0]) os_printf("   Don't transmit more frames until switch occurs\n");
				break;
			case 38:
				os_printf("  802.11h Measurement Request\n");
				break;
			case 39:
				os_printf("  802.11h Measurement Report\n");
				break;
			case 40:
				os_printf("  802.11h Quiet\n");
				break;
			case 41:
				os_printf("  802.11h IBSS DFS\n");
				break;
			case 42:
				os_printf("  802.11g ERP Information\n");
				if(data[0] & 0x80) os_printf("   NonERP STAs are present in this BSS\n");
				if(data[0] & 0x40) os_printf("   Use Protection Mechanism\n");
				if(data[0] & 0x20) os_printf("   Do not use short preamble\n");
				break;
			case 43:
				os_printf("  802.11e TS Delay\n");
				break;
			case 44:
				os_printf("  802.11e TCLAS Processing\n");
				break;
			case 46:
				os_printf("  802.11e QoS Capability\n");
				break;
			case 48:
				os_printf("  802.11i RSN:\n");
				break;
			case 50:
				os_printf("  802.11g Extended Supported Rates (Kbit/s)\n   ");
				for(i = 0; i < ie->length; i++) 
					os_printf("%u, ", data[i] * 500);
				os_printf("%c%c\n", (char) 8, (char) 8);		
				break;
				
			case 221:
				decode_80211_vendor_ie(ie);
				break;
			default:
				os_printf("  Unknown IE Element ID, 0x%02x\n", ie->id);
		}
		len -= sizeof(ieee80211_ie) + ie->length;
		pkt = ((char *)pkt + sizeof(ieee80211_ie) + ie->length);
	}
}


void ieee80211_print_reason_code(uint16_t code) 
{
	switch (code) {
		case 0: os_printf("Reserved"); break;
		case 1: os_printf("Unspecified Reason"); break;
		case 2: os_printf("Previous authentication no longer valid"); break;
		case 3: os_printf("Deauthenticated because sending station is leaving or has left IBSS or BSS"); break;
		case 4: os_printf("Disassociated due to inactivity"); break;
		case 5: os_printf("Disassociated because AP is unable to handle all currently associated stations"); break;
		case 6: os_printf("Class 2 frame received from nonauthenticated station"); break;
		case 7: os_printf("Class 3 frame received from nonassociated station"); break;
		case 8: os_printf("Disassociated because AP is leaving (or has left) BSS"); break;
		case 9: os_printf("Station requesting (re)association is not authenticated with responding station"); break;
		default: os_printf("Unknown reason code: %u\n", code);
	}
}

 
void ieee80211_print_status_code(uint16_t code) 
{
	switch (code) {
		case 0: os_printf("Successful"); break;
		case 1: os_printf("Unspecified failure"); break;
		case 10: os_printf("Cannot support all requested capabilities in the Capability Information field"); break;
		case 11: os_printf("Reassociation denied due to inablity to confirm that association exists"); break;
		case 12: os_printf("Association denied due to reason outside the scope of this standard"); break;
		case 13: os_printf("Responding station does not support the specified authentication algorithm"); break;
		case 14: os_printf("Received an Authentication frame with authentication transaction sequence number outside of expected sequence"); break;
		case 15: os_printf("Authentication rejected because of channege failure"); break;
		case 16: os_printf("Authentication rejected due to timeout waiting for next frame in sequence"); break;
		case 17: os_printf("Association denied because AP is unable to handle additional associated stations"); break;
		case 18: os_printf("Association denied due to requesting station not supporting all of the data rates in the BSSBasicRates parameter"); break;
		default: os_printf("Unknown status code: %u", code);
	}
}

/* Decodes a capability info field */
 void decode_80211_capinfo(ieee80211_capinfo *c) 
 {
	os_printf(" 802.11MAC: Capability Info:");
	if (c->ess) os_printf(" ESS");
	if (c->ibss) os_printf(" IBSS");
	if (c->cf_pollable) os_printf(" CF-POLLABLE");
	if (c->cf_poll_req) os_printf(" CF-POLL-REQ");
	if (c->privacy) os_printf(" PRIVACY");
	if (c->short_preamble) os_printf(" SHORT-PREAMBLE");
	if (c->pbcc) os_printf (" PBCC");
	if (c->channel_agility) os_printf (" CHANNEL-AGILITY");
	if (c->spectrum_mgmt) os_printf( " SPECTRUM-MGMT");
	if (c->qos) os_printf(" QoS");
	if (c->short_slot_time) os_printf (" SHORT-SLOT-TIME");
	if (c->apsd) os_printf(" APSD");
	if (c->dsss_ofdm) os_printf (" DSSS-OFDM");
	if (c->delayed_block_ack) os_printf(" DELAYED-BLK-ACK");
	if (c->immediate_block_ack) os_printf(" IMMEDIATE-BLK-ACK");
	os_printf("\n");
}
	
/* Decodes a beacon (or a probe response) */
 void decode_80211_beacon(const char *pkt, unsigned len) 
 {
	ieee80211_beacon *b = (ieee80211_beacon *)pkt;
	//os_printf("sizeof(ieee80211_beacon):%d\n", sizeof(ieee80211_beacon));
	//os_printf("len:%d\n", len);
	if (len < sizeof(ieee80211_beacon)) 
	{
		os_printf(" 802.11MAC: [Truncated]\n");
		return;
	}
	
	//os_printf(" 802.11MAC: Timestamp = %" PRIu64 "\n", b->ts);
	os_printf(" 802.11MAC: Timestamp = %ld\n", b->ts);
	os_printf(" 802.11MAC: Beacon Interval = %u\n", b->interval);
	decode_80211_capinfo(&b->capinfo);
	os_printf(" 802.11MAC: Information Elements:\n");
	//decode_80211_information_elements((char *) pkt + sizeof(ieee80211_beacon), len - sizeof(ieee80211_beacon));	

	if (len > 116)
	{
		decode_80211_information_elements((char *) pkt + 116, len - 116);	
	}

}

 void decode_80211_assoc_request(const char *pkt, unsigned len) 
 {
	ieee80211_assoc_req *a = (ieee80211_assoc_req *) pkt;
	
	if (len < sizeof(ieee80211_assoc_req)) {
		os_printf(" [Truncated association request]\n");
		return;
	}

	decode_80211_capinfo(&a->capinfo);
	os_printf(" 802.11MAC: Listen Interval = %u beacon intervals\n", a->listen_interval);
	os_printf(" 802.11MAC: Information Elements:\n");
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_assoc_req), len - sizeof(ieee80211_assoc_req));
}

 void decode_80211_assoc_response(const char *pkt, unsigned len) 
 {
	ieee80211_assoc_resp *r = (ieee80211_assoc_resp *) pkt;

	if (len < sizeof(ieee80211_assoc_resp)) {
		os_printf(" [Truncated association response]\n");
		return;
	}
	decode_80211_capinfo(&r->capinfo);
	os_printf(" 802.11MAC: Status Code = ");
	ieee80211_print_status_code(r->status_code);
	/* AID has two most significant bits set to 1 */
	os_printf("\n 802.11MAC: Association ID = %u\n", r->assoc_id & 0x3FFF);
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_assoc_resp), len-sizeof(ieee80211_assoc_resp));
}
	
 void decode_80211_reassoc_request(const char *pkt, unsigned len) 
 {
	ieee80211_reassoc_req *r = (ieee80211_reassoc_req *) pkt;

	if (len < sizeof(ieee80211_reassoc_req)) {
		os_printf(" [Truncated reassociation request]\n");
		return;
	}
	decode_80211_capinfo(&r->capinfo);
	os_printf(" 802.11MAC: Listen Interval = %u beacon intervals\n", r->listen_interval);
	os_printf(" 802.11MAC: Current AP address = %s\n", macaddr(r->current_address));
	os_printf(" 802.11MAC: Information Elements:\n");
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_reassoc_req), len - sizeof(ieee80211_reassoc_req));
}

 void decode_80211_authentication_frame(const char *pkt, unsigned len) 
 {
	ieee80211_auth *auth = (ieee80211_auth *)pkt;
	if(len < sizeof(ieee80211_auth)) {
		os_printf(" [Truncated authentication frame]\n");
		return;
	}
	os_printf(" 802.11MAC: Authentication algorithm number = %u\n", auth->auth_algo_num);
	os_printf(" 802.11MAC: Authentication transaction sequence number = %u\n", auth->auth_trans_seq_num);
	os_printf(" 802.11MAC: Status Code = ");
	ieee80211_print_status_code(auth->status_code);
	os_printf("\n 802.11MAC: Information Elements:\n");
	decode_80211_information_elements((char *)pkt + sizeof(ieee80211_auth), len - sizeof(ieee80211_auth));

}

 void decode_80211_mgmt(const char *pkt, unsigned len) 
 {
	ieee80211_mgmt_frame *mgmt = (ieee80211_mgmt_frame *)pkt;
	const char *data;
	
	os_printf(" 802.11MAC: Management frame: ");
	
	if (len < sizeof(ieee80211_mgmt_frame)) {
		os_printf("[Truncated]\n");
		return;
	}

	switch (mgmt->ctl.subtype) {
		case 0: os_printf("association request"); break;
		case 1: os_printf("association response"); break;
		case 2: os_printf("reassociation request"); break;
		case 3: os_printf("reassociation response"); break;
		case 4: os_printf("probe request"); break;
		case 5: os_printf("probe response"); break;
		case 8: os_printf("beacon"); break;
		case 9: os_printf("ATIM"); break;
		case 10: os_printf("disassociation"); break;
		case 11: os_printf("authentication"); break;
		case 12: os_printf("deauthentication"); break;
		case 13: os_printf("action"); break;
		default: os_printf("RESERVED"); break;
	}
	
	os_printf("\n 802.11MAC: Duration = %u us\n", mgmt->duration);
	os_printf(" 802.11MAC: DA       = %s\n", macaddr(mgmt->addr1));
	os_printf(" 802.11MAC: SA       = %s\n", macaddr(mgmt->addr2));
	os_printf(" 802.11MAC: BSSID    = %s\n", macaddr(mgmt->addr3));
	os_printf(" 802.11MAC: fragment no. = %u, sequence no. = %u\n",
			(mgmt->seq_ctrl & 0x000F) ,
			(mgmt->seq_ctrl & 0xFFF0) >> 4);

	switch (mgmt->ctl.subtype) {
		case 0:
			decode_80211_assoc_request(pkt, len);
			break;	
		case 1:
			decode_80211_assoc_response(pkt, len);
			break;
		case 2:
			decode_80211_reassoc_request(pkt, len);
			break;
		case 3:
			/* Reassoc response == assoc response */
			decode_80211_assoc_response(pkt, len);
			break;
		case 4:
			os_printf("Probe Request\n");
			os_printf("=========================================================\n");
			hex_print((char *)pkt, len);
			if (len > 116)
			{
				decode_80211_information_elements((char *) pkt + 116, len - 116);	
			}
			//decode_80211_information_elements((char *)pkt + sizeof(ieee80211_mgmt_frame), len - sizeof(ieee80211_mgmt_frame));
			break;
		case 5:
			/* Probe response == beacon frame */
			decode_80211_beacon(pkt, len);

			break;
		case 8:
			os_printf("Beacon\n");
			os_printf("=========================================================\n");
			hex_print((char *)pkt, len);
			decode_80211_beacon(pkt, len);
			break;
		case 10:
			data = (pkt + sizeof(ieee80211_mgmt_frame));
			os_printf(" 802.11MAC: Reason Code = ");
			ieee80211_print_reason_code((uint16_t) ((data[0] << 8) | (data[1])));
			os_printf("\n");
			break;
						    
		case 11:
			decode_80211_authentication_frame(pkt, len);
			break;
		case 12:
			data = (pkt + sizeof(ieee80211_mgmt_frame));
			os_printf(" 802.11MAC: Reason Code = ");
			ieee80211_print_reason_code((uint16_t) ((data[0] << 8) | (data[1])));
			os_printf("\n");
			break;
		default:
			os_printf(" 802.11MAC: Subtype %u decoder not implemented\n", mgmt->ctl.subtype);
	}

	os_printf("\n");

}

 void decode_80211_ctrl(const char *pkt, unsigned len) 
 {
	ieee80211_ctrl_frame_1addr *ctrl1 = (ieee80211_ctrl_frame_1addr *) pkt;
	ieee80211_ctrl_frame_2addr *ctrl2 = (ieee80211_ctrl_frame_2addr *) pkt;
	os_printf(" 802.11MAC: Control frame: ");
	
	if (len < sizeof(ieee80211_ctrl_frame_1addr)) {
		os_printf("[Truncated]\n");
		return;
	}
	
	switch (ctrl1->ctl.subtype) {
		case 8: 
			os_printf("BlockAckReq\n"); 
			break;
		case 9: 
			os_printf("BlockAck\n"); 
			break;
		case 10: 
			os_printf("PS-Poll\n"); 
			//os_printf(" 802.11MAC: AID = 0x%04x\n", ntohs(ctrl1->duration));
			os_printf(" 802.11MAC: BSSID = %s\n", macaddr(ctrl1->addr1));
			break;
		case 11:
			os_printf("RTS\n");
 
			if (len < sizeof(ieee80211_ctrl_frame_2addr)) {
				os_printf("[Truncated]\n");
				return;
			}

			os_printf(" 802.11MAC: RA = %s\n", macaddr(ctrl2->addr1));
			os_printf(" 802.11MAC: TA = %s\n", macaddr(ctrl2->addr2));
			break;
		case 12: 
			os_printf("CTS\n"); 
			os_printf(" 802.11MAC: RA = %s\n", macaddr(ctrl1->addr1));
			break;
		case 13:
			os_printf("ACK\n"); 
			os_printf(" 802.11MAC: RA = %s\n", macaddr(ctrl1->addr1));
			break;
		case 14:
			os_printf("CF-End\n"); 

			if (len < sizeof(ieee80211_ctrl_frame_2addr)) {
				os_printf("[Truncated]\n");
				return;
			}

			os_printf(" 802.11MAC: RA = %s\n", macaddr(ctrl2->addr1));
			os_printf(" 802.11MAC: BSSID = %s\n", macaddr(ctrl2->addr2));
			break;
		case 15:
			os_printf("CF-End + CF-Ack\n"); 

			if (len < sizeof(ieee80211_ctrl_frame_2addr)) {
				os_printf("[Truncated]\n");
				return;
			}

			os_printf(" 802.11MAC: RA = %s\n", macaddr(ctrl2->addr1));
			os_printf(" 802.11MAC: BSSID = %s\n", macaddr(ctrl2->addr2));
			break;
		default:
			os_printf("RESERVED"); 
			break;
	}

}




 void decode_80211_data(const char *pkt, unsigned len) 
 {
	ieee80211_data_frame *data = (ieee80211_data_frame *) pkt;
	ieee80211_qos_data_frame *qos = (ieee80211_qos_data_frame *)pkt;
	ieee80211_payload *pld; 
	uint32_t hdrlen = 0;
	
	os_printf(" 802.11MAC: Data frame: ");
	
	if (len < sizeof(ieee80211_data_frame_3)) {
		os_printf("[Truncated]\n");
		return;
	}

	switch (data->ctl.subtype) {
		case 0: os_printf("Data"); break;
		case 1: os_printf("Data + CF-Ack"); break;
		case 2: os_printf("Data + CF-Poll"); break;
		case 3: os_printf("Data + CF-Ack + CF-Poll"); break;
		case 4: os_printf("Null (no data)"); break;
		case 5: os_printf("CF-Ack (no data)"); break;
		case 6: os_printf("CF-Poll (no data)"); break;
		case 7: os_printf("CF-Ack + CF-Poll (no data)"); break;
		case 8: os_printf("QoS Data"); break;
		case 9: os_printf("QoS Data + CF-Ack"); break;
		case 10: os_printf("QoS Data + CF-Poll"); break;
		case 11: os_printf("QoS Data + CF-Ack + CF-Poll"); break;
		case 12: os_printf("QoS Null (no data)"); break;
			 /* subtype 13 is reserved */
		case 14: os_printf("QoS CF-Poll (no data)"); break;
		case 15: os_printf("Qos CF-Ack + CF-Poll (no data)"); break;

		default: os_printf("RESERVED"); break;
	}

	os_printf("\n 802.11MAC: duration = %u us\n", data->duration);
	os_printf(" 802.11MAC: fragment no. = %u, sequence no. = %u\n",
			(data->seq_ctrl & 0x000F) ,
			(data->seq_ctrl & 0xFFF0) >> 4);

	hdrlen = sizeof(ieee80211_data_frame_3);
	
	if (! data->ctl.from_ds && ! data->ctl.to_ds) {
		os_printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr1));
		os_printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr2));
		os_printf(" 802.11MAC: BSSID   = %s\n", macaddr(data->addr3));
	} else if ( ! data->ctl.from_ds && data->ctl.to_ds) {
		os_printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr3));
		os_printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr2));
		os_printf(" 802.11MAC: BSSID   = %s\n", macaddr(data->addr1));
	} else if ( data->ctl.from_ds && ! data->ctl.to_ds) {
		os_printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr1));
		os_printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr3));
		os_printf(" 802.11MAC: BSSID   = %s\n", macaddr(data->addr2));
	} else {
		/* Check to make sure we have a four-address frame first */
		if (len < sizeof(ieee80211_data_frame)) {
			os_printf(" 802.11MAC: [Truncated]\n");
			return;
		}
		os_printf(" 802.11MAC: DA      = %s\n", macaddr(data->addr3));
		os_printf(" 802.11MAC: SA      = %s\n", macaddr(data->addr4));
		os_printf(" 802.11MAC: TA      = %s\n", macaddr(data->addr2));
		os_printf(" 802.11MAC: RA      = %s\n", macaddr(data->addr1));
		hdrlen = sizeof(ieee80211_data_frame); /* 4 addr header */
	}


	if (data->ctl.subtype >= 8) { 
		os_printf(" 802.11e: QoS = 0x%04x\n", qos->qos);
		if (len > sizeof(ieee80211_qos_data_frame)) 
			hdrlen = sizeof(ieee80211_qos_data_frame);
	}
	
	if (len > hdrlen) {
		int payload_offset = 0;
		uint16_t ethertype = 0;
		pld = (ieee80211_payload *) ((char *)pkt + hdrlen) ;
		/*
		if (ntohs(pld->ethertype) == 0xaaaa) 
		{
			// 802.11 payload contains an 802.2 LLC/SNAP header 
			libtrace_llcsnap_t *llcsnap = (libtrace_llcsnap_t *) pld;
			os_printf(" 802.2: DSAP = 0x%x, SSAP = 0x%x, OUI = 0x%x, Type = 0x%x\n", 
					llcsnap->dsap, llcsnap->ssap, llcsnap->oui, ntohs(llcsnap->type));
			payload_offset = sizeof(libtrace_llcsnap_t);
			ethertype = ntohs(llcsnap->type);
		} else {
			// 802.11 payload contains an Ethernet II frame 
			os_printf(" 802.11MAC: Payload ethertype = 0x%04x\n", ntohs(pld->ethertype));
			payload_offset = sizeof(pld->ethertype);
			ethertype = ntohs(pld->ethertype);
		}*/
		//decode_next((char *) pkt + hdrlen + payload_offset, 
		//		len - hdrlen - payload_offset, "eth", ethertype);
	}

	
}


//void decode(int link_type UNUSED, const char *pkt, unsigned len) 
void decode(const char *pkt, unsigned len) 
{
	ieee80211_frame_control *fc;
	
	if (len < sizeof(ieee80211_frame_control)) {
		os_printf(" 802.11MAC: Truncated at frame control field\n");
		return;
	}

	fc = (ieee80211_frame_control *) pkt;	

	os_printf(" 802.11MAC: %02x\t ", pkt[0]);

	os_printf("proto = %d, type = %d, subtype = %d, ", fc->version, fc->type, fc->subtype);

	os_printf("flags =");
	if (fc->to_ds) os_printf(" toDS");
	if (fc->from_ds) os_printf(" fromDS");
	if (fc->more_frag) os_printf(" moreFrag");
	if (fc->retry) os_printf(" retry");
	if (fc->power) os_printf(" pwrMgmt");
	if (fc->more_data) os_printf(" moreData");
	if (fc->wep) os_printf(" WEP");
	if (fc->order) os_printf(" order");

	os_printf("\n");
	switch (fc->type) 
	{
		case 0:
			decode_80211_mgmt(pkt, len);
			break;
		case 1:
			//decode_80211_ctrl(pkt, len);
			break;
		case 2:
			//decode_80211_data(pkt, len);
			//os_printf("decode_80211_data\n");
			break;
		case 3:
			os_printf(" Unable to decode frame type %u, dumping rest of packet\n", fc->type);
			//decode_next(pkt + sizeof(ieee80211_frame_control), len - sizeof(ieee80211_frame_control), "unknown", 0);
			
			break;
	}

}


