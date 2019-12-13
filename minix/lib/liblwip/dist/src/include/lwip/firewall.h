//
// Created by davis on 2018-12-06.
//

#ifndef LWIP_HDR_FIREWALL_H
#define LWIP_HDR_FIREWALL_H

#include "lwip/pbuf.h"
#include "lwip/ip.h"

int ip4_fw_incoming(const ip4_addr_t *src, const ip4_addr_t *dest);
int ip4_fw_outgoing(const ip4_addr_t *src, const ip4_addr_t *dest);
int fw_add_rule(const ip4_addr_t *src, const ip4_addr_t *dest, char* p_name, uint8_t action);
#endif //LWIP_HDR_FIREWALL_H
