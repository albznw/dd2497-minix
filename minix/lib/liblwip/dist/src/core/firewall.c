#include "lwip/firewall.h"
#include "lwip/opt.h"
#include <minix/fwdec.h>


int ip4_query_firewall(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (fwdec_ip4(src->addr, dest->addr) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}
