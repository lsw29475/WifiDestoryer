#include "linux.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <net/if_arp.h>

#include "byteorder.h"

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef NULL_MAC
#define NULL_MAC        "\x00\x00\x00\x00\x00\x00"
#endif

bool set_monitor(char* iface,int fd)
{
    int unused;
    iwreq wrq;

    memset(&wrq,0x00,sizeof(iwreq));
    strncpy(wrq.ifr_name,iface,IFNAMSIZ);
    wrq.ifr_name[IFNAMSIZ-1]=0;
    wrq.u.mode=IW_MODE_MONITOR;

    if(ioctl(fd,SIOCSIWMODE,&wrq)<0)
    {
        printf("set mode monitor fail\n");
        return false;
    }

    if(!fork())
    {
        close(0);
        close(1);
        close(2);
        unused=chdir("/");
        execlp("iwpriv","iwpriv",iface,"monitor_type","1",NULL);
        exit(1);
    }
    wait(NULL);

    if (!fork())
	{
		close(0);
		close(1);
		close(2);
		unused = chdir("/");
		execlp("iwpriv", "iwpriv", iface, "prismhdr", "1", NULL);
		exit(1);
	}
	wait(NULL);

	if (!fork())
	{
		close(0);
		close(1);
		close(2);
		unused = chdir("/");
		execlp("iwpriv", "iwpriv", iface, "set_prismhdr", "1", NULL);
		exit(1);
	}
	wait(NULL);

	return true;
}

bool openraw(WIFI* pWifi,char* iface,int fd)
{
    ifreq ifr;
    iwreq wrq;
    sockaddr_ll sll;
    packet_mreq mr;

    memset(&ifr,0x00,sizeof(ifreq));
    strncpy(ifr.ifr_name,iface,sizeof(ifr.ifr_name)-1);

    if(ioctl(fd,SIOCGIFINDEX,&ifr)<0)
    {
        printf("Interface: %s ioctl(SIOCGIFINDEX) fail\n",iface);
        return false;
    }

    memset(&sll,0x00,sizeof(sockaddr_ll));
    sll.sll_family=AF_PACKET;
    sll.sll_ifindex=ifr.ifr_ifindex;

    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0)
    {
        printf("Interface: %s ioctl(SIOCGIFINDEX) fail\n",iface);
        return false;
    }

    memset(&wrq,0x00,sizeof(iwreq));
    strncpy(wrq.ifr_name,iface,IFNAMSIZ);
    wrq.ifr_name[IFNAMSIZ-1]=0;

    if(ioctl(fd,SIOCGIWMODE,&wrq)<0)
    {
        wrq.u.mode=IW_MODE_MONITOR;
    }

    if((ifr.ifr_hwaddr.sa_family!=ARPHRD_IEEE80211 &&
        ifr.ifr_hwaddr.sa_family!=ARPHRD_IEEE80211_PRISM &&
        ifr.ifr_hwaddr.sa_family!=ARPHRD_IEEE80211_FULL) ||
       (wrq.u.mode!=IW_MODE_MONITOR))
    {
        if(!set_monitor(iface,fd))
        {
            ifr.ifr_flags &= ~(IFF_UP | IFF_BROADCAST | IFF_RUNNING);
            if(ioctl(fd,SIOCSIFFLAGS,&ifr)<0)
            {
                printf("Interface: %s ioctl(SIOCSIFFLAGS) fail\n");
                return false;
            }

            if(!set_monitor(iface,fd))
            {
                printf("set monitor fail\n");
                return false;
            }
        }
    }

    if((ifr.ifr_flags | IFF_UP | IFF_BROADCAST | IFF_RUNNING)!=ifr.ifr_flags)
    {
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;
        if(ioctl(fd,SIOCSIFFLAGS,&ifr)<0)
        {
            printf("Interface: %s ioctl(SIOCSIFFLAGS) fail\n",iface);
            return false;
        }
    }

    if(bind(fd,(sockaddr*)&sll,sizeof(sockaddr_ll))<0)
    {
        printf("Interface: %s bind(ETH_P_ALL) fail\n");
        return false;
    }

    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0)
    {
        printf("Interface: %s ioctl(SIOCGIFHWADDR) fail\n");
        return false;
    }

    if(ifr.ifr_hwaddr.sa_family!=ARPHRD_IEEE80211 &&
       ifr.ifr_hwaddr.sa_family!=ARPHRD_IEEE80211_PRISM &&
       ifr.ifr_hwaddr.sa_family!=ARPHRD_IEEE80211_FULL)
    {
        if(ifr.ifr_hwaddr.sa_family==1)
        {
            printf("APR linktype is set to 1(Ethernet)\n");
        }
        else
        {
            printf("Unsupported hardware link type\n");
        }

        return  false;
    }

    memset(&mr,0x00,sizeof(mr));
    mr.mr_ifindex=sll.sll_ifindex;
    mr.mr_type=PACKET_MR_PROMISC;

    if(setsockopt(fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr))<0)
    {
        printf("setsocketopt (PACKET_MR_PROMISC) fail\n");
        return false;
    }

    return true;
}

bool linux_set_channel(WIFI* pWifi,int channel)
{
    iwreq wrq;

    memset(&wrq,0x00,sizeof(iwreq));
    strncpy(wrq.ifr_name,pWifi->iFaceName,IFNAMSIZ);

    wrq.ifr_name[IFNAMSIZ-1]=0;
    wrq.u.freq.m=(double)channel;
    wrq.u.freq.e=(double)0;

    if(ioctl(pWifi->fd_in,SIOCSIWFREQ,&wrq)<0)
    {
        usleep(10000);
        if(ioctl(pWifi->fd_in,SIOCSIWFREQ,&wrq)<0)
        {
            printf("Interface: wlan1mon ioctl(SIOCSIWFREQ) fail,channel: %d\n",channel);
            return false;
        }
    }

    return true;
}

bool do_linux_open(WIFI* pWifi)
{
    if((pWifi->fd_in=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
    {
        printf("open raw socket fail\n");
        return false;
    }

    if((pWifi->fd_out=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
    {
        printf("open raw socket fail\n");
        return false;
    }

    if(!openraw(pWifi,pWifi->iFaceName,pWifi->fd_out))
    {
        printf("open raw fail\n");
        return false;
    }

    pWifi->fd_in=pWifi->fd_out;

    if(!linux_set_channel(pWifi,6))
    {
        printf("set channel fail\n");
        return false;
    }

    return true;
}

void do_linux_close(WIFI* pWifi)
{
    if(pWifi->fd_in)
    {
        close(pWifi->fd_in);
    }

    if(pWifi->fd_out)
    {
        close(pWifi->fd_out);
    }
}

int linux_read(WIFI* pWifi,unsigned char* buf,int Count,RX_INFO* pRx_info)
{
    unsigned char tempbuf[4096];
    int caplen;
    int n;
    IEEE80211_RADIOTAP_HEADER* pRadioHeader;

    if(Count>sizeof(tempbuf))
    {
        return -1;
    }

    if((caplen=read(pWifi->fd_in,tempbuf,Count))<0)
    {
        return -1;
    }

    memset(buf,0x00,sizeof(buf));
    pRadioHeader=(IEEE80211_RADIOTAP_HEADER*)tempbuf;

    n=le16_to_cpu(pRadioHeader->it_len);

    if(n<=0 || n>=caplen)
    {
        return -1;
    }

    memcpy(buf,tempbuf+n,caplen);

    return caplen;
}
