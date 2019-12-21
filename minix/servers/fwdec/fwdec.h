#ifndef _FWDEC_H_
#define _FWDEC_H_

#include <sys/types.h>
#include <minix/config.h>
#include <minix/ds.h>
#include <minix/bitmap.h>
#include <minix/param.h>
#include <regex.h>

#define FWDEC_DEBUG 0//Set to 1 to enable additional info on stdout, 0 to disable

#define MODE_NOTSET 0
#define MODE_WHITELIST 1
#define MODE_BLACKLIST 2

/* Ip protocol definitions - Keep these numbers in sync with minix/lib/liblwip/dist/src/include/lwip/prot/ip.h*/
#define IP_PROTO_ICMP    1
#define IP_PROTO_IGMP    2
#define IP_PROTO_UDP     17
#define IP_PROTO_UDPLITE 136
#define IP_PROTO_TCP     6

#define IP_ANY 0

#define FW_RULE_REJECT 1
#define FW_RULE_ACCEPT 2

#define FW_FLAG_ANY_IP      0x1
#define FW_FLAG_IP_IN_RANGE 0x2
#define FW_FLAG_EXACT_IP    0x4




struct fw_rule {
  uint32_t ip_start;
  uint32_t ip_end;
  char *p_name;
  uint8_t action;
  struct fw_rule *next;
};

typedef struct fw_rule fw_rule_t;

#endif // _FWDEC_H_
