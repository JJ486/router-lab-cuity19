#include "eui64.h"
#include <stdint.h>
#include <stdlib.h>

in6_addr eui64(const ether_addr mac) {
  in6_addr res = {0};
  // TODO
  res.__u6_addr.__u6_addr8[0]=0xFE;
  res.__u6_addr.__u6_addr8[1]=0x80;
  res.__u6_addr.__u6_addr8[11]=0xFF;
  res.__u6_addr.__u6_addr8[12]=0xFE;
  for (int i = 1; i < 4; i++)
  {
    res.__u6_addr.__u6_addr16[i]=0;// 3~8B=0
    res.__u6_addr.__u6_addr8[7+i]=mac.octet[i-1];//9~11B=MAC1~3B
    res.__u6_addr.__u6_addr8[12+i]=mac.octet[i+2];//14~16B=MAC4~6B
  }
  __uint8_t correctBit=0xFD|~(res.__u6_addr.__u6_addr8[8]&2);
  res.__u6_addr.__u6_addr8[8]=(res.__u6_addr.__u6_addr8[8]|0x02)&correctBit;//Set it to correct vlu by and
  return res;
}