#ifndef _IWIFIDESTORYER_LINUX_H
#define _IWIFIDESTORYER_LINUX_H

#include <stdbool.h>
#include <inttypes.h>

#pragma pack(1)
typedef struct _WIFI
{
    int fd_in;
    int fd_out;
    char iFaceName[64];
} WIFI, *PWIFI;
#pragma pack()

#pragma pack(1)
typedef struct _RX_INFO
{
    uint64_t ri_mactime;
    int32_t ri_power;
    int32_t ri_noise;
    uint32_t ri_channel;
    uint32_t ri_freq;
    uint32_t ri_rate;
    uint32_t ri_antenna;
} RX_INFO, *PRX_INFO;
#pragma pack()

#pragma pack(1)
typedef struct _IEEE80211_RADIOTAP_HEADER
{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} IEEE80211_RADIOTAP_HEADER, *PIEEE80211_RADIOTAP_HEADER;
#pragma pack()

bool do_linux_open(WIFI* pWifi);
void do_linux_close(WIFI* pWifi);
bool linux_set_channel(WIFI* pWifi,int channel);
int linux_read(WIFI* pWifi,unsigned char* buf,int count,RX_INFO* pRx_info);

#endif // _IWIFIDESTORYER_LINUX_H
