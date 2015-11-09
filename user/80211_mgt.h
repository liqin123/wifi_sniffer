#include "80211hdr.h"

typedef struct MacHeader
{
	unsigned short wFrameCtl;
	unsigned short wDurationID;
	unsigned char abyAddr1[WLAN_ADDR_LEN];	//Receiver Address (= Destination Address)
	unsigned char abyAddr2[WLAN_ADDR_LEN];	//Transmitter Address (=Source Address)
	unsigned char abyAddr3[WLAN_ADDR_LEN];	//BSSID
	unsigned short wSeqCtl;

}MACHEADER, *PMACHEADER;

typedef struct Frame
{
	//struct MacHeader* pMacHeader;
	MACHEADER Header;
	//char * frame_body;

}FRAME, *PFRAME;

// Information Element Types

typedef struct tagWLAN_IE 
{
    unsigned char   byElementID;
    unsigned char   len;
} __attribute__ ((__packed__))
WLAN_IE, *PWLAN_IE;

// Service Set Identity (SSID)
typedef struct tagWLAN_IE_SSID 
{
    unsigned char   byElementID;
    unsigned char   len;
    unsigned char   abySSID[1];
} __attribute__ ((__packed__))
WLAN_IE_SSID, *PWLAN_IE_SSID;

typedef struct tagWLAN_IE_SUPP_RATES {
    unsigned char   byElementID;
    unsigned char   len;
    unsigned char   abyRates[1];
} __attribute__ ((__packed__))
WLAN_IE_SUPP_RATES,  *PWLAN_IE_SUPP_RATES;

// Probe Request
typedef struct Probe_Req_Frame 
{
	MACHEADER		Header;
	PWLAN_IE_SSID		   pSSID;
	PWLAN_IE_SUPP_RATES	 pSuppRates;
	PWLAN_IE_SUPP_RATES	 pExtSuppRates;

} PROBEREQFRAME, *PPROBEREQFRAME;

void decode_probe_req(char * pBuf);
void decode_test(char * pBuf);
