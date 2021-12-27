#ifndef _FWDEC_PROTO_H
#define _FWDEC_PROTO_H

#include <stdbool.h>

#define FW_IP 1
#define FW_TCP 2
#define FW_UDP 3
#define FW_ICMP 4
#define FW_RAW 5

/* Default values that matches any value if set. */
#define TYPE_ANY 0
#define IP_ANY 0
#define PORT_ANY 0
#define PNAME_ANY "\0"
#define DIR_ANY 0
// TODO5: since our root user is 0 and we never really need "any user" we should remove this.
#define UID_ANY 0

/* ID:s for the rule chains */
// Must be same as the values defined in "minix/include/sys/fwctl.h"
#define PRIVILEGED_CHAIN_ID 1
#define GLOBAL_CHAIN_ID 2
#define USER_CHAIN_ID 3

/* Function prototypes. */

/* main.c */
int main(int argc, char** argv);

/* fwdec.c */
int check_packet(const int type, const uint32_t src_ip, const uint32_t dest_ip,
                 const uint16_t src_port, const uint16_t dest_port, const char* p_name, const uint64_t flags, uid_t uid);

int check_packet_match(const uint8_t type, const uint32_t src_ip, const uint16_t port, const char* p_name, uint8_t direction, uid_t uid);

int check_tcp_match(const uint32_t src_ip, const uint16_t port, const char* p_name, uint64_t flags, uint8_t direction, uid_t uid);

int add_rule(uint8_t direction, uint8_t type, uint8_t action,
             uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name,
			 uint32_t chain_id, int index, uint32_t uid);
int delete_rule(uint32_t chain_id, int index);
void list_rules(int chain_id);

int sef_cb_init_fresh(int type, sef_init_info_t* info);

#endif
