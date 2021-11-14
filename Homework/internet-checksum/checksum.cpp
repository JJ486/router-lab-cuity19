#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static uint16_t customAdd(uint16_t a, uint16_t b)
{
  if ((uint16_t)(a + b) < a)
  {
    // printf("%04X,%04X,%04X\n", a,b, (uint16_t)(a + b + 1));
    return a + b + 1;
  }
  // printf("%04X,%04X,%04X\n", a,b, (uint16_t)(a + b));
  return a + b;
}
static uint16_t calculatePacketChecksum(uint8_t *packet, size_t len)
{
  uint16_t *packet16 = (uint16_t *)packet;
  uint16_t sum = 0;

  for (int i = 0; i < len / 2; i++)
    sum = customAdd(sum, htons(packet16[i])); //, printf("%04X %04X\n", htons(packet16[i]), sum);
  return sum;
}
static uint16_t calculateIpv6PsudoHeaderChecksum(uint8_t *packet, size_t len)
{
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  uint16_t sum = 0;
  for (int i = 0; i < 8; i++)
  {
    uint16_t temp = ip6->ip6_src.s6_addr[2 * i];
    temp = (temp << 8) + ip6->ip6_src.s6_addr[2 * i + 1];
    sum = customAdd(sum, temp);
    // printf("%04X %04X\n", temp, sum);
    temp = ip6->ip6_dst.s6_addr[2 * i];
    temp = (temp << 8) + ip6->ip6_dst.s6_addr[2 * i + 1];
    sum = customAdd(sum, temp);
    // printf("%04X %04X\n", temp, sum);
  } //Calculating checksum for Addresses
  sum = customAdd(sum, ip6->ip6_nxt);
  sum = customAdd(sum, (uint16_t)len - 40);
  return sum;
}
bool validateAndFillChecksum(uint8_t *packet, size_t len)
{
  // TODO
  /*Dealing with odd bytes. This will not break memory integrity since from main the packet field is off full possible length*/
  bool validateResult = false;
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  uint16_t PsudoHeaderChecksum = calculateIpv6PsudoHeaderChecksum(packet, len);
  if (len % 2)
    packet[len++] = 0;

  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP)
  {
    // printf("UDP\n");
    // UDP
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    uint16_t originalSum = udp->uh_sum;
    udp->uh_sum = 0;
    uint16_t calcSum = calculatePacketChecksum((uint8_t *)udp, len - sizeof(ip6_hdr));
    calcSum=customAdd(calcSum, PsudoHeaderChecksum);
    calcSum=htons(calcSum);
    validateResult = (customAdd(calcSum, originalSum) == 0xFFFF);
    if(!originalSum)
      validateResult=false;
    calcSum = ~calcSum;
    if(!calcSum)
      calcSum=0xFFFF;
    udp->uh_sum = calcSum;
    // length: udp->uh_ulen
    // checksum: udp->uh_sum
  }
  else if (nxt_header == IPPROTO_ICMPV6)
  {
    // ICMPv6
    // printf("ICMP\n");
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    uint16_t originalSum = icmp->icmp6_cksum;
    icmp->icmp6_cksum = 0;
    uint16_t calcSum = calculatePacketChecksum((uint8_t *)icmp, len - sizeof(ip6_hdr));
    calcSum=customAdd(calcSum, PsudoHeaderChecksum);
    calcSum=htons(calcSum);
    validateResult = (customAdd(calcSum, originalSum) == 0xFFFF);
    calcSum = ~calcSum;
    icmp->icmp6_cksum = calcSum;
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum
  }
  else
  {
    assert(false);
  }
  return validateResult;
}
