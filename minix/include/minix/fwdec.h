/* Prototypes and definitions for FWDEC interface. */

#ifndef _MINIX_FWDEC_H
#define _MINIX_FWDEC_H

#include <sys/types.h>
#include <minix/endpoint.h>

/* fwdec.c */

/* U32 */
int fwdec_ip4_incoming(uint32_t src_ip, uint32_t dest_ip);
int fwdec_ip4_outgoing(uint32_t src_ip, uint32_t dest_ip);
int fwdec_add_rule(uint32_t src_ip, uint32_t dest_ip, char* p_name, uint8_t action);
#endif /* _MINIX_FWDEC_H */
