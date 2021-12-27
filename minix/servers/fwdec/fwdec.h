#ifndef _FWDEC_H_
#define _FWDEC_H_

#include <minix/bitmap.h>
#include <minix/config.h>
#include <minix/ds.h>
#include <minix/param.h>
#include <regex.h>
#include <sys/types.h>

#define FWDEC_DEBUG  //Uncomment this line to enable debug output

#define MODE_NOTSET 0
#define MODE_WHITELIST 1
#define MODE_BLACKLIST 2

/* Ip protocol definitions - Keep these numbers in sync with minix/lib/liblwip/dist/src/include/lwip/prot/ip.h*/
#define IP_PROTO_ICMP 1
#define IP_PROTO_IGMP 2
#define IP_PROTO_UDP 17
#define IP_PROTO_UDPLITE 136
#define IP_PROTO_TCP 6

#define FW_RULE_ACCEPT 1
#define FW_RULE_REJECT 2

#define FW_FLAG_ANY_IP 0x1
#define FW_FLAG_IP_IN_RANGE 0x2
#define FW_FLAG_EXACT_IP 0x4

#endif  // _FWDEC_H_
