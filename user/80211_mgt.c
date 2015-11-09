#include "80211_mgt.h"
#include "osapi.h"
#include "driver/uart.h"


void decode_probe_req(char * pBuf)
{
	PWLAN_IE pElment = (PWLAN_IE)pBuf;
	os_printf("Element ID: 0x%02x", pBuf[0]);
	os_printf("Length: 0x%02x", pBuf[1]);

}

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

void decode_test(char * pBuf)
{
//	os_printf ("%02x:", pBuf[4]);
//	os_printf ("%02x:", pBuf[5]);
//	os_printf ("%02x:", pBuf[6]);
//	os_printf ("%02x", pBuf[7]);

//	os_printf("\n");
	//PMACHEADER pHdr = (PMACHEADER)pBuf;
	//os_printf("%02x", pHdr->abyAddr1[0]);
/*
	os_printf("[0]: 0x%02x\n", pBuf[0]);
	os_printf("[1]: 0x%02x\n", pBuf[1]);
	os_printf("[2]: 0x%02x\n", pBuf[2]);
	os_printf("[3]: 0x%02x\n", pBuf[3]);
	os_printf("[4]: 0x%02x\n", pBuf[4]);
	os_printf("[5]: 0x%02x\n", pBuf[5]);

	os_printf("[ver]: 0x%02x\n", pBuf[0] & 0x03);
	os_printf("[type]: 0x%02x\n", pBuf[0] & 0x0C);
	os_printf("[subtype]: 0x%02x\n", pBuf[0] & 0xF0);
*/
	PFRAME pFrame = (PFRAME)pBuf;

	int Frame_Type = pBuf[0];
	//int Frame_Type = (pFrame->Header.wFrameCtl  >> 8) & 0x00FF;


	int ver = (Frame_Type >> 6) & 0x03;
	int type = (Frame_Type >> 4) & 0x03;
	int subtype = Frame_Type & 0x0F;
	os_printf("----------\n");

	//os_printf("all:%02x\n", pFrame->Header.wFrameCtl);
	os_printf("Version:%02x\n", ver);
	os_printf("type:%02x\n", type);
	os_printf("sub type:%02x\n", subtype);
	os_printf("Destination Address: %02x:%02x:%02x:%02x:%02x:%02x\n", pFrame->Header.abyAddr1[0], pFrame->Header.abyAddr1[1], pFrame->Header.abyAddr1[2], pFrame->Header.abyAddr1[3], pFrame->Header.abyAddr1[4], pFrame->Header.abyAddr1[5] );
	os_printf("Transmitter Address: %02x:%02x:%02x:%02x:%02x:%02x\n", pFrame->Header.abyAddr2[0], pFrame->Header.abyAddr2[1], pFrame->Header.abyAddr2[2], pFrame->Header.abyAddr2[3], pFrame->Header.abyAddr2[4], pFrame->Header.abyAddr2[5] );
	os_printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", pFrame->Header.abyAddr3[0], pFrame->Header.abyAddr3[1], pFrame->Header.abyAddr3[2], pFrame->Header.abyAddr3[3], pFrame->Header.abyAddr3[4], pFrame->Header.abyAddr3[5] );


	if (type == WLAN_TYPE_MGR)
	{
		if (subtype == WLAN_FSTYPE_ASSOCREQ)
		{
			os_printf("WLAN_FSTYPE_ASSOCREQ\n");
		}
		if (subtype == WLAN_FSTYPE_ASSOCRESP)
		{
			os_printf("WLAN_FSTYPE_ASSOCRESP\n");
		}
		if (subtype == WLAN_FSTYPE_REASSOCREQ)
		{
			os_printf("WLAN_FSTYPE_REASSOCREQ\n");
		}
		if (subtype == WLAN_FSTYPE_REASSOCRESP)
		{
			os_printf("WLAN_FSTYPE_REASSOCRESP\n");
		}
		if (subtype == WLAN_FSTYPE_PROBEREQ)
		{
			os_printf("WLAN_FSTYPE_PROBEREQ\n");
			os_printf("==============================================================\n");
			//os_printf()
			hex_print(pBuf, 200);
			//PPROBEREQFRAME pProbe = (PPROBEREQFRAME)pBuf;
			//os_printf("%x\n", pProbe->pSSID->abySSID[0]);
			//os_printf("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x \n", pBuf[118], pBuf[119], pBuf[120], pBuf[121], pBuf[122]);
			//os_printf("==============================================================\n");
			//if (pBuf[24] == 0x00)
			//{
			//	os_printf("AP: %s\n", pBuf[26]);
			//}
			decode_probe_req(&pBuf[24]);
		}
		if (subtype == WLAN_FSTYPE_PROBERESP)
		{
			os_printf("WLAN_FSTYPE_PROBERESP\n");
		}
		if (subtype == WLAN_FSTYPE_BEACON)
		{
			os_printf("WLAN_FSTYPE_BEACON\n");
		}
		if (subtype == WLAN_FSTYPE_ATIM)
		{
			os_printf("WLAN_FSTYPE_ATIM\n");
		}
		if (subtype == WLAN_FSTYPE_DISASSOC)
		{
			os_printf("WLAN_FSTYPE_DISASSOC\n");
		}
		if (subtype == WLAN_FSTYPE_AUTHEN)
		{
			os_printf("WLAN_FSTYPE_AUTHEN\n");
		}
		if (subtype == WLAN_FSTYPE_DEAUTHEN)
		{
			os_printf("WLAN_FSTYPE_DEAUTHEN\n");
		}
		if (subtype == WLAN_FSTYPE_ACTION)
		{
			os_printf("WLAN_FSTYPE_ACTION\n");
		}
		/*
		switch(subtype)
		{
			case WLAN_FSTYPE_ASSOCREQ:
				os_printf("WLAN_FSTYPE_ASSOCREQ\n");
				break;
			case WLAN_FSTYPE_ASSOCRESP:
				os_printf("WLAN_FSTYPE_ASSOCRESP\n");
				break;
			case WLAN_FSTYPE_REASSOCREQ:
				os_printf("WLAN_FSTYPE_REASSOCREQ\n");
				break;
			case WLAN_FSTYPE_REASSOCRESP:
				os_printf("WLAN_FSTYPE_REASSOCRESP\n");
				break;
			case WLAN_FSTYPE_PROBEREQ:
				os_printf("WLAN_FSTYPE_PROBEREQ\n");
				break;
			case WLAN_FSTYPE_PROBERESP:
				os_printf("WLAN_FSTYPE_PROBERESP\n");
				break;
		}
		*/
	}

	//if (WLAN_GET_FC_FTYPE(pFrame->Header.wFrameCtl) == WLAN_TYPE_MGR && WLAN_GET_FC_FSTYPE(pFrame->Header.wFrameCtl) == WLAN_FSTYPE_PROBEREQ)
	//{
		/* code */
	//}

	//os_printf("%02x\t%02x\n", pFrame->Header.wFrameCtl, Frame_Type);	//correct
	//os_printf("0x%02x\tVer: 0x%02x\t Type: 0x%02x, SubType: 0x%02x\n", Frame_Type, Frame_Type & 0xC0, Frame_Type & 0x30, Frame_Type & 0x0F);

	/*
	os_printf("Version: %02x\t", pFrame->Header.wFrameCtl & 0xC000);
	os_printf("Type: %02x\t", pFrame->Header.wFrameCtl & 0x3000);
	os_printf("SubType: %02x\t", pFrame->Header.wFrameCtl & 0x0F00);
	os_printf("\n------------------------------------------------\n");

	if ((pFrame->Header.wFrameCtl & 0x3F00) == 0x04)
	{
		os_printf("Found PROBE REQUEST!\n");
	}
	*/
}