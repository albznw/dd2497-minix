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

int sef_cb_init_fresh(int type, sef_init_info_t *info);

#endif
