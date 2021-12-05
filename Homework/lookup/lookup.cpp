#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

std::vector<RoutingTableEntry> routeTable;
static int maxMatchLen(const in6_addr &lhs, const in6_addr &rhs, int maxLen = 128)
{
  int maxMatchLength = 0;

  for (int i = 0; i < maxLen / 8 + 1; i++)
  {
    if (lhs.s6_addr[i] == rhs.s6_addr[i])
    {
      maxMatchLength += 8;
      continue;
    }
    for (int j = 0; j < 8; j++, maxMatchLength++)
    {
      if ((lhs.s6_addr[i] & (0x80 >> j)) != (rhs.s6_addr[i] & (0x80 >> j)))
      {
        return maxMatchLength > maxLen ? maxLen : maxMatchLength;
      }
    }
  }
  return maxLen;
}
static void printAddr(const in6_addr &src)
{
  char nexthop_buffer[128];
  inet_ntop(AF_INET6, &src, nexthop_buffer,
            sizeof(nexthop_buffer));
  printf("%s\n", nexthop_buffer);
}
static std::vector<RoutingTableEntry>::iterator maxMatch(const in6_addr &target)
{
  std::vector<RoutingTableEntry>::iterator it = routeTable.begin();
  int maxMatchLength = -1;
  std::vector<RoutingTableEntry>::iterator maxMatchIt = routeTable.end();
  for (; it != routeTable.end(); it++)
  {
    if (maxMatchLength >= (int)it->len)
      continue;
    if (maxMatchLength == 128)
      return maxMatchIt;
    int tempMaxLen = maxMatchLen(target, it->addr);
    tempMaxLen = tempMaxLen > it->len ? it->len : tempMaxLen;
    if (tempMaxLen < it->len)
      continue;
    if (tempMaxLen > maxMatchLength)
    {
      // printf("tempMax=%d\n",tempMaxLen);
      // printAddr(it->addr);
      maxMatchIt = it;
      maxMatchLength = tempMaxLen > it->len ? it->len : tempMaxLen;
      if (maxMatchLength == 128)
        return maxMatchIt;
    }
  }
  return maxMatchIt;
}
std::vector<RoutingTableEntry>::iterator getEntry(const in6_addr &addr, int len)
{
  for (auto it = routeTable.begin(); it != routeTable.end(); it++)
  {
    if (it->len == len)
    {
      int i = 0;
      for (; i < 16; i++)
      {
        if (it->addr.s6_addr[i] != addr.s6_addr[i])
          break;
      }
      if (i == 16)
      {
        return it;
      }
    }
  }
  return routeTable.end();
}
void update(bool insert, const RoutingTableEntry entry)
{
  auto it = routeTable.begin();
  for (; it != routeTable.end(); it++)
  {
    if (it->len == entry.len)
    {
      int i = 0;
      for (; i < 16; i++)
      {
        if (it->addr.s6_addr[i] != entry.addr.s6_addr[i])
          break;
      }
      if (i == 16)
      {
        if (insert)
        {
          if(it->learnedAddr==entry.learnedAddr){
            it->metric=entry.metric;
          }
          else if (it->metric > entry.metric)
          {
            routeTable.erase(it);
            routeTable.push_back(entry);
          }
        }
        else
        {
          routeTable.erase(it);
        }
        return;
      }
    }
  }
  if (insert && entry.metric!=16 &&it == routeTable.end())
    routeTable.push_back(entry);
  // TODO
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index)
{
  // TODO
  auto it = maxMatch(addr);
  if (it == routeTable.end())
    return false;
  for (int i = 0; i < 16; i++)
  {
    nexthop->s6_addr[i] = it->nexthop.s6_addr[i];
  }
  *if_index = it->if_index;
  return true;
}

int mask_to_len(const in6_addr mask)
{
  // TODO
  short prefLen = 128;
  for (int i = 3; i >= 0; i--)
  {
    for (int j = 3; j >= 0; j--)
    {
      for (int k = 0; k < 8; k++)
      {
        if (mask.s6_addr[i * 4 + j] & (1 << k))
          goto outside;
        prefLen--;
      }
    }
  }
outside:
  return prefLen;
}

in6_addr len_to_mask(int len)
{
  if (len > 128 || len < 0)
    return {};
  in6_addr returnedMask;
  for (int i = 0; i < 16; i++)
  {
    returnedMask.s6_addr[i] = 0;
  }

  for (int i = 0; i < len / 8; i++)
  {
    returnedMask.s6_addr[i] = 0xFF;
  }
  for (int i = 0; i < len % 8; i++)
  {
    returnedMask.s6_addr[len / 8] |= 0x80 >> i;
  }
  return returnedMask;
}
