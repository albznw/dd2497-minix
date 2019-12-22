//
// Created by davis on 2018-12-06.
//

#ifndef LWIP_HDR_FIREWALL_H
#define LWIP_HDR_FIREWALL_H

#include "lwip/pbuf.h"
#include "lwip/ip.h"

int ip4_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest);
int ip4_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest);
int tcp_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp, uint64_t flags);
int tcp_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp);
int udp_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp);
int udp_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest, int src_port, int dest_port, endpoint_t user_endp);
int raw_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest, endpoint_t user_endp);
int raw_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest, endpoint_t user_endp);
int icmp_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest);
int icmp_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest);

#endif //LWIP_HDR_FIREWALL_H
