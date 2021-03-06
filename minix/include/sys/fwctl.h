#ifndef _SYS__FWCTL_H
#define _SYS__FWCTL_H

#include <sys/types.h>

#define NO_USER_ID 999

// Must be same as the values defined in "minix/servers/fwdec/fwchain.h"
// TODO5: would probably be better to fix so that we can include fwchain.h instead
#define PRIVILEGED_CHAIN_ID 1
#define GLOBAL_CHAIN_ID 2
#define USER_CHAIN_ID 3

// Must be same as the values defined in "minix/servers/fwdec/fwchain.h"
#define IN_RULE 1
#define OUT_RULE 2

// Must be same as the values defined in "minix/servers/fwdec/fwchain.h"
#define ACCEPT_PACKET 1
#define DROP_PACKET 2

int fwdec_add_rule(uint8_t direction, uint8_t type, uint8_t action,
						uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name,
						uint32_t chain_id, int index, int uid);

int fwdec_delete_rule(uint32_t chain_id, int index);

int fwdec_list_rules(int chain_id);

#endif /* _SYS__SVRCTL_H */
