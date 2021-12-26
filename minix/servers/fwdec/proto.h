#ifndef _FWDEC_PROTO_H
#define _FWDEC_PROTO_H

#include <stdbool.h>

#define FW_IP   0
#define FW_TCP  1
#define FW_UDP  2
#define FW_ICMP 3
#define FW_RAW  4

/* Function prototypes. */

/* main.c */
int main(int argc, char **argv);


/* fwdec.c */
int check_packet(const int type, const uint32_t src_ip, const uint32_t dest_ip,
                  const uint16_t src_port, const uint16_t dest_port, const char* p_name, const uint64_t flags, uid_t uid);

int check_packet_match(const uint8_t type, const uint32_t src_ip, const uint16_t port, const char* p_name, uint8_t direction, uid_t uid);

int check_tcp_match(const uint32_t src_ip, const uint16_t port, const char* p_name, uint64_t flags, uint8_t direction, uid_t uid);

int add_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
				uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name);
int delete_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
					uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name);
void list_rules(void);

int sef_cb_init_fresh(int type, sef_init_info_t *info);

#endif
