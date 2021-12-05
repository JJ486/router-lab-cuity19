#include "protocol.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
RipErrorCode disassemble(const uint8_t *packet, uint32_t len,
                         RipPacket *output) {
  // TODO
  const uint8_t* currentHead=packet;
  ip6_hdr ip6=*(ip6_hdr*)packet;
  // printf("\n");
  // printf("%02X\n",htons(ip6.ip6_plen));
  if(len<40||htons(ip6.ip6_plen)+40!=len)
    return RipErrorCode::ERR_LENGTH;
  if(ip6.ip6_nxt!=IPPROTO_UDP)
    return RipErrorCode::ERR_IP_NEXT_HEADER_NOT_UDP;
  if(htons(ip6.ip6_plen)<8)
    return RipErrorCode::ERR_LENGTH;
  currentHead+=40;
  udphdr udp=*(udphdr*)currentHead;

  if(htons(udp.uh_dport)!=521||htons(udp.uh_sport)!=521)
    return RipErrorCode::ERR_BAD_UDP_PORT;
  if((htons(udp.uh_ulen)-8-4)%20)
    return RipErrorCode::ERR_LENGTH;
  currentHead+=8;
  ripng_hdr ripng=*(ripng_hdr*)currentHead;
  if(ripng.command!=1&&ripng.command!=2)
    return RipErrorCode::ERR_RIP_BAD_COMMAND;
  if(ripng.version!=1)
    return RipErrorCode::ERR_RIP_BAD_VERSION;
  if(ripng.zero!=0)
    return RipErrorCode::ERR_RIP_BAD_ZERO;
  currentHead+=4;
  output->numEntries=(len-52)/20;
  output->command=ripng.command;
  for (int i = 0; i < output->numEntries; i++)
  {
    output->entries[i]=*(ripng_entry*)(currentHead+20*i);
    ripng_entry* thisEntry=&output->entries[i];
    if(thisEntry->metric==0xFF){
      if(thisEntry->prefix_len!=0)
        return RipErrorCode::ERR_RIP_BAD_PREFIX_LEN;
      if(thisEntry->route_tag!=0)
        return RipErrorCode::ERR_RIP_BAD_ROUTE_TAG;
    }
    else{
      if(thisEntry->metric<1||thisEntry->metric>16)
        return RipErrorCode::ERR_RIP_BAD_METRIC;
      if(thisEntry->prefix_len>128)
        return RipErrorCode::ERR_RIP_BAD_PREFIX_LEN;
      uint16_t prefLen=128;
      for (int i = 3; i >=0; i--)
      {
        for (int j = 3; j >= 0; j--)
        {
          for (int k = 0; k < 8; k++)
          {
            if(thisEntry->prefix_or_nh.s6_addr[i*4+j]&(1<<k))
              goto outside;
            prefLen--;
          }
          
        }
      }
      outside:
      if(thisEntry->prefix_len!=prefLen)
        return RipErrorCode::ERR_RIP_INCONSISTENT_PREFIX_LENGTH;
    }
    /* code */
  }
  return RipErrorCode::SUCCESS;
}

uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO
  buffer[0]=rip->command;
  buffer[1]=1;
  buffer[2]=buffer[3]=0;
  buffer+=4;
  for (int i = 0; i < rip->numEntries; i++)
  {
    for (int j = 0; j < 16 ; j++)
    {
        buffer[j]=rip->entries[i].prefix_or_nh.s6_addr[j];
    }
    buffer+=16;
    ((uint16_t*)buffer)[0]=rip->entries[i].route_tag;
    buffer[2]=rip->entries[i].prefix_len;
    buffer[3]=rip->entries[i].metric;
    buffer+=4;
  }
  return 4+rip->numEntries*20;
}