//
// Created by davis on 2018-12-06.
//

#ifndef LWIP_HDR_FIREWALL_H
#define LWIP_HDR_FIREWALL_H

#include "lwip/pbuf.h"
#include "lwip/ip.h"

int ip4_query_firewall(const ip4_addr_t *src, const ip4_addr_t *dest);

#endif //LWIP_HDR_FIREWALL_H
