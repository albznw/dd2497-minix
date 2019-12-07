/* Prototypes and definitions for FWDEC interface. */

#ifndef _MINIX_FWDEC_H
#define _MINIX_FWDEC_H

#include <sys/types.h>
#include <minix/endpoint.h>

/* fwdec.c */

/* U32 */
int fwdec_ip4(uint32_t src_ip, uint32_t dest_ip);

#endif /* _MINIX_FWDEC_H */
