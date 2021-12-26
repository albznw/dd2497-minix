#ifndef _FWDEC_RULE_H_
#define _FWDEC_RULE_H_

#define MAX_PRIORITY 0xFF
#define MED_PRIORITY 0xAA
#define MIN_PRIORITY 0x00

#define MAX_NAME_LEN 16

#define NO_UID (uid_t)0x10

#define IN_RULE 0
#define OUT_RULE 1
#define BOTH_WAYS 2

/**
 * Let fw_rules be a doubly linked list that exists on the HEAP.
 */
typedef struct fw_rule {
  uint8_t type;
  uint8_t priority;
  uint8_t action;
  uint32_t ip_start;
  uint32_t ip_end;
  uint16_t port;
  char p_name[MAX_NAME_LEN];
  struct fw_rule *next;
  struct fw_rule *prev;
} fw_rule;

// Struct for firewall chains
typedef struct fw_chain_rule {
  uint8_t type;
  uint8_t action;
  uint8_t direction;  // IN_RULE or OUT_RULE
  uid_t user;
  uint32_t ip_start;
  uint32_t ip_end;
  uint16_t port;
  char p_name[MAX_NAME_LEN];
} fw_chain_rule;

typedef struct fw_chain_entry {
  struct fw_chain_rule *rule;
  struct fw_chain_entry *prev;
  struct fw_chain_entry *next;
} fw_chain_entry;

typedef struct fw_chain {
  struct fw_chain_entry *head_entry;
} fw_chain;

fw_rule *find_matching_rule(fw_rule **head_ref, const uint8_t type,
                            const uint32_t ip_addr, const uint16_t port,
                            const char *p_name);

void get_ip_string(char *buf, uint32_t buf_len, uint32_t ip_addr);

void push_rule(fw_rule **head_ref, const uint32_t ip_start,
               const uint32_t ip_end, const uint8_t type, const uint16_t port,
               const uint8_t priority, const uint8_t action,
               const char *p_name);

void remove_rule(fw_rule **head_ref, const uint32_t ip_start,
                 const uint32_t ip_end, const uint8_t type, const uint16_t port,
                 const uint8_t priority, const uint8_t action,
                 const char *p_name);

void add_chain_rule(fw_chain *chain, fw_chain_rule *new_rule, int index);

void insert_chain_rule(fw_chain *chain, int index, const uint32_t ip_start,
                       const uint32_t ip_end, const uint8_t type,
                       const uint16_t port, const uid_t uid,
                       const uint8_t action, const char *p_name,
                       const uint8_t direction);

void remove_chain_rule(fw_chain *chain, int index);

fw_chain_rule* find_matching_chain_rule(fw_chain *chain, const uint8_t type,
                            const uint32_t ip_addr, const uint16_t port,
                            const char *p_name, const uint8_t direction, const uid_t uid);

void print_chain_rules(fw_chain *chain);


#endif