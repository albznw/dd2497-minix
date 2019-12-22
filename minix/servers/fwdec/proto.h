#ifndef _FWDEC_PROTO_H
#define _FWDEC_PROTO_H

#include <stdbool.h>

/* Function prototypes. */

/* main.c */
int main(int argc, char **argv);

/* fwdec.c */
int check_packet(const int type, const uint32_t src_ip, const uint32_t dest_ip,
                  const uint16_t src_port, const uint16_t dest_port, const char* p_name, const uint64_t flags);

int check_incoming_ip4(const uint32_t src_ip, const char *p_name);
int check_outgoing_ip4(const uint32_t dest_ip, const char *p_name);
int check_incoming_tcp(const uint32_t src_ip, const char *p_name, uint64_t flags);

int add_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
				uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name);
int delete_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
					uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name);

void list_rules(void);
int sef_cb_init_fresh(int type, sef_init_info_t *info);

#endif
