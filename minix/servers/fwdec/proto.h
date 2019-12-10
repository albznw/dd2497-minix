#ifndef _FWDEC_PROTO_H
#define _FWDEC_PROTO_H

#include <stdbool.h>

/* Function prototypes. */

/* main.c */
int main(int argc, char **argv);

/* fwdec.c */
int check_incoming_ip4(uint32_t src_ip);
int check_outgoing_ip4(uint32_t dest_ip);

// int check_ip4_headers(bool incoming, uint32_t src_ip, uint32_t dst_ip);
// int check_ip4_headers(uint32_t src_ip, uint32_t dst_ip);
int sef_cb_init_fresh(int type, sef_init_info_t *info);

#endif
