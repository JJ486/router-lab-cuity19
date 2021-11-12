#include "eui64.h"
#include <stdint.h>
#include <stdlib.h>

in6_addr eui64(const ether_addr mac) {
  in6_addr res = {0};
  // TODO
  res.s6_addr[0]=0xFE;
  res.s6_addr[1]=0x80;
  res.s6_addr[11]=0xFF;
  res.s6_addr[12]=0xFE;
  for (int i = 1; i < 4; i++)
  {
    res.s6_addr[7+i]=mac.ether_addr_octet[i-1];//9~11B=MAC1~3B
    res.s6_addr[12+i]=mac.ether_addr_octet[i+2];//14~16B=MAC4~6B
  }
  __uint8_t correctBit=0xFD|~(res.s6_addr[8]&2);
  res.s6_addr[8]=(res.s6_addr[8]|0x02)&correctBit;//Set it to correct vlu by and
  return res;
}