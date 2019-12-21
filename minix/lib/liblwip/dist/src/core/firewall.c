#include "lwip/firewall.h"
#include "lwip/opt.h"
#include <minix/fwdec.h>

int ip4_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (fwdec_ip4_incoming(src->addr, dest->addr) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int ip4_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (fwdec_ip4_outgoing(src->addr, dest->addr) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int fw_add_rule(const ip4_addr_t *src, const ip4_addr_t *dest, char* p_name, uint8_t action){
  return fwdec_add_rule(src -> addr,dest -> addr, p_name, action);
}


