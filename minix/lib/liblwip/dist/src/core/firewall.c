#include "lwip/firewall.h"
#include "lwip/opt.h"
#include <minix/fwdec.h>

int ip4_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (fwdec_query_packet(FWDEC_QUERY_IP4_INC, src->addr, dest->addr, 0, 0, 0, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int ip4_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (fwdec_query_packet(FWDEC_QUERY_IP4_OUT, src->addr, dest->addr, 0, 0, 0, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}
