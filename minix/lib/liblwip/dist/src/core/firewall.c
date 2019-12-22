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

int tcp_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp, uint64_t flags)
{
  if (fwdec_query_packet(FWDEC_QUERY_TCP_INC, src->addr, dest->addr, user_endp, src_port, dest_port, flags) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int tcp_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp)
{
  if (fwdec_query_packet(FWDEC_QUERY_TCP_OUT, src->addr, dest->addr, user_endp, src_port, dest_port, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int udp_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp)
{
  if (fwdec_query_packet(FWDEC_QUERY_UDP_INC, src->addr, dest->addr, user_endp, src_port, dest_port, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int udp_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp)
{
  if (fwdec_query_packet(FWDEC_QUERY_UDP_OUT, src->addr, dest->addr, user_endp, src_port, dest_port, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int raw_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest, endpoint_t user_endp)
{
  if (fwdec_query_packet(FWDEC_QUERY_RAW_INC, src->addr, dest->addr, user_endp, 0, 0, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int raw_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest, endpoint_t user_endp)
{
  if (fwdec_query_packet(FWDEC_QUERY_RAW_OUT, src->addr, dest->addr, user_endp, 0, 0, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int icmp_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (fwdec_query_packet(FWDEC_QUERY_ICMP_INC, src->addr, dest->addr, 0, 0, 0, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}

int icmp_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (fwdec_query_packet(FWDEC_QUERY_ICMP_OUT, src->addr, dest->addr, 0, 0, 0, 0) != LWIP_KEEP_PACKET) {
    return LWIP_DROP_PACKET;
  }

  return LWIP_KEEP_PACKET;
}
