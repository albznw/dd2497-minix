/**
 * @file
 * Common IPv4 and IPv6 code
 *
 * @defgroup ip IP
 * @ingroup callbackstyle_api
 * 
 * @defgroup ip4 IPv4
 * @ingroup ip
 *
 * @defgroup ip6 IPv6
 * @ingroup ip
 * 
 * @defgroup ipaddr IP address handling
 * @ingroup infrastructure
 * 
 * @defgroup ip4addr IPv4 only
 * @ingroup ipaddr
 * 
 * @defgroup ip6addr IPv6 only
 * @ingroup ipaddr
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#if LWIP_IPV4 || LWIP_IPV6

#include "lwip/ip_addr.h"
#include "lwip/ip.h"

/** Global data for both IPv4 and IPv6 */
struct ip_globals ip_data;

#if LWIP_IPV4 && LWIP_IPV6

const ip_addr_t ip_addr_any_type = IPADDR_ANY_TYPE_INIT;

/**
 * @ingroup ipaddr
 * Convert IP address string (both versions) to numeric.
 * The version is auto-detected from the string.
 *
 * @param cp IP address string to convert
 * @param addr conversion result is stored here
 * @return 1 on success, 0 on error
 */
int
ipaddr_aton(const char *cp, ip_addr_t *addr)
{
  if (cp != NULL) {
    const char* c;
    for (c = cp; *c != 0; c++) {
      if (*c == ':') {
        /* contains a colon: IPv6 address */
        if (addr) {
          IP_SET_TYPE_VAL(*addr, IPADDR_TYPE_V6);
        }
        return ip6addr_aton(cp, ip_2_ip6(addr));
      } else if (*c == '.') {
        /* contains a dot: IPv4 address */
        break;
      }
    }
    /* call ip4addr_aton as fallback or if IPv4 was found */
    if (addr) {
      IP_SET_TYPE_VAL(*addr, IPADDR_TYPE_V4);
    }
    return ip4addr_aton(cp, ip_2_ip4(addr));
  }
  return 0;
}

/**
 * @ingroup lwip_nosys
 * If both IP versions are enabled, this function can dispatch packets to the correct one.
 * Don't call directly, pass to netif_add() and call netif->input().
 */
err_t
ip_input(struct pbuf *p, struct netif *inp)
{
  printf("%p\n",(void *) &p);
  if (p != NULL) {
	
    if (IP_HDR_GET_VERSION(p->payload) == 6) {
      return ip6_input(p, inp);
    }
    checkPacket(p);
    return ip4_input(p, inp);
  }
  return ERR_VAL;
}
int
checkPacket(struct pbuf *p){
  void *data;
  data = p->payload;
  int * payload = data;
  //unsigned char bytes[4];
  //printf("start\n");
  unsigned int hlen = (*payload) & 0xF;
  unsigned int srcprt =*(payload+hlen) & 0xFF;
  unsigned int srcprt2 =*(payload+hlen)>>8 & 0xFF;
  unsigned int dstprt =*(payload+hlen)>>16 & 0xFF;
  unsigned int dstprt2 =*(payload+hlen)>>24 & 0xFF;

  unsigned int srcIp = *(payload + 3);
  unsigned int dstIp = *(payload + 4);
  dstprt = (dstprt<<4) +dstprt2;
  srcprt = (srcprt<<4) +srcprt2;
  //printf("srcprt:%d,dstprt%d\n",srcprt,dstprt);
  dstIp =((dstIp>>24)&0xFF)|((dstIp<<8)&0xFF0000)|((dstIp>>8)&0xff00)|((dstIp<<24)&0xFF000000);
    /*  bytes[3] = *(&dstIp)  & 0xFF;
        bytes[2] = *(&dstIp)>>8 & 0xFF;
        bytes[1] = *(&dstIp)>>16 & 0xFF;
        bytes[0] = *(&dstIp)>>24 & 0xFF;
	printf("%d.%d.%d.%d intval: %d\n",bytes[3],bytes[2],bytes[1],bytes[0],dstIp);
    */
   srcIp =((srcIp>>24)&0xFF)|((srcIp<<8)&0xFF0000)|((srcIp>>8)&0xff00)|((srcIp<<24)&0xFF000000);
     /*   bytes[3] = *(&srcIp)  & 0xFF;
        bytes[2] = *(&srcIp)>>8 & 0xFF;
        bytes[1] = *(&srcIp)>>16 & 0xFF;
        bytes[0] = *(&srcIp)>>24 & 0xFF;
	printf("%d.%d.%d.%d intval: %d\n",bytes[3],bytes[2],bytes[1],bytes[0],srcIp);
     */
  /*printf("ipheader length:%d,srcprt:%d,dstprt:%d, \n",hlen,srcprt*16+srcprt2,dstprt*16+dstprt2);
  printf("pointer + hlen = %p, pointer = %p\n",(void *) (payload+hlen),(void *) (payload));
  for(int i= 0;i<6;){
        bytes[3] = *(payload + i) & 0xFF;
        bytes[2] = *(payload + i)>>8 & 0xFF;
        bytes[1] = *(payload + i)>>16 & 0xFF;
        bytes[0] = *(payload + i)>>24 & 0xFF;
	printf("pointer = %p: %d.%d.%d.%d\n",(void *) (payload+i), bytes[3],bytes[2],bytes[1],bytes[0]);
	i = i+1;
  }*/
return 0;
}

#endif /* LWIP_IPV4 && LWIP_IPV6 */

#endif /* LWIP_IPV4 || LWIP_IPV6 */
