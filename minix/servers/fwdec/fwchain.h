#ifndef _FWDEC_CHAIN_H_
#define _FWDEC_CHAIN_H_

#include <sys/types.h>

/* The different types of network packets */
#define FW_IP 1
#define FW_TCP 2
#define FW_UDP 3
#define FW_ICMP 4
#define FW_RAW 5

/* If a rule matches incoming or outgoing packets */
// TODO5: would probably be better to fix so that we can include fwctl.h instead
// TODO5: maybe it works with <sys/fwctl.h> (see minix/commands/firewall/firewall.c) since it is already in include folder?
// Must be same as the values defined in "minix/include/sys/fwctl.h"
#define IN_RULE 1
#define OUT_RULE 2

/* Whether the rule states to accept or drop a matching packet */
// TODO5: would probably be better to fix so that we can include fwctl.h instead
// TODO5: maybe it works with <sys/fwctl.h> (see minix/commands/firewall/firewall.c) since it is already in include folder?
// Must be same as the values defined in "minix/include/sys/fwctl.h"
#define FW_RULE_ACCEPT 1
#define FW_RULE_REJECT 2

/* Default values that matches any value if set. */
#define TYPE_ANY 0
#define IP_ANY 0
#define PORT_ANY 0
#define PNAME_ANY "\0"
#define DIR_ANY 0
#define UID_ANY -1

/* ID:s for the rule chains */
// Must be same as the values defined in "minix/include/sys/fwctl.h"
#define PRIVILEGED_CHAIN_ID 1
#define GLOBAL_CHAIN_ID 2
#define USER_CHAIN_ID 3

// Must be kept in sync with the max length defined by "minix/commands/firewall/firewall.c" and the max name length allowed in the
// IPC messages
#define MAX_NAME_LEN 16

/**
  Struct for individual rules
*/
typedef struct fw_chain_rule {
  uint8_t type;
  uint8_t action;
  uint8_t direction;  // IN_RULE or OUT_RULE
  // TODO5: Currently user ID is signed in most places but not in this struct and not when adding rules to it. 
  // While a user ID should always be positive we want to be able to represent no particular user by using the ID -1.
  // However, currently we have no need to add rules specifying "no particular user", so the rules are still saved with a signed user ID.
  uid_t user;
  uint32_t ip_start;
  uint32_t ip_end;
  uint16_t port;
  char p_name[MAX_NAME_LEN];
} fw_chain_rule;

/**
  Struct for entries (rules) in a chain
*/
typedef struct fw_chain_entry {
  struct fw_chain_rule *rule;
  struct fw_chain_entry *prev;
  struct fw_chain_entry *next;
} fw_chain_entry;

/**
  Struct for chains that hold rules. Chain_id specify what type of chain it is 
*/
typedef struct fw_chain {
  struct fw_chain_entry *head_entry;
  uid_t chain_id;
} fw_chain;

#endif