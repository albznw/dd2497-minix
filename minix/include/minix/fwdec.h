/* Prototypes and definitions for FWDEC interface. */

#ifndef _MINIX_FWDEC_H
#define _MINIX_FWDEC_H

#include <sys/types.h>
#include <minix/endpoint.h>

/* fwdec.c */

/* U32 */
int fwdec_query_packet(int type, uint32_t src_ip, uint32_t dest_ip, endpoint_t user_endp,
						uint16_t src_port, uint16_t dest_port, uint64_t flags);

#endif /* _MINIX_FWDEC_H */
