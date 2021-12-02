#ifndef _FWDEC_RULE_H_
#define _FWDEC_RULE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PRIORITY 0xFF
#define MED_PRIORITY 0xAA
#define MIN_PRIORITY 0x00

#define MAX_NAME_LEN 16

#define NOUID (uid_t)0x10

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

#define IN_CHAIN 0
#define OUT_CHAIN 1
// Struct for firewall chains
typedef struct fw_chain_rule {
  uint8_t type;
  uint8_t action;
  uint8_t direction;  // IN_CHAIN or OUT_CHAIN
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

/**
 * Adds a new rule in the chain, if the wanted index is not found the
 * rule will be placed in the end of the chain. A fast way to add rules
 * to the end of the list is to add them at index -1.
 *
 * @param new_rule pointer to the new rule on the heap
 * @param index wanted index
 */
void add_chain_rule(fw_chain *chain, fw_chain_rule *new_rule, int index) {
  printf("Adding new rule %d %d %s", new_rule->type, new_rule->action,
         new_rule->direction ? "OUT" : "IN");

  fw_chain_entry *c_entry = chain->head_entry;
  fw_chain_entry *new_entry = (fw_chain_entry *)malloc(sizeof(fw_chain_entry));

  // Create a new entry from the added rule
  new_entry->rule = new_rule;
  new_entry->prev = NULL;
  new_entry->next = NULL;

  // No entries currently exists
  if (chain->head_entry == NULL) {
    // If we have no rules in the chain yet
    new_entry->prev = NULL;
    new_entry->next = NULL;
    chain->head_entry = new_entry;
    return;
  }

  int c_index = 0;
  fw_chain_entry *last_entry = NULL;

  while (c_entry) {
    if (index == c_index) {
      // Add new entry before c_entry

      // entry before the new entry;
      fw_chain_entry *tmp_prev = c_entry->prev;
      // New references of c_entry
      c_entry->prev = new_entry;
      // New references of new entry
      new_entry->next = c_entry;
      new_entry->prev = tmp_prev;
      // New reference of previous
      if (tmp_prev != NULL) {
        tmp_prev->next = new_entry;
      }
      return;
    }
    c_index++;
    last_entry = c_entry;
    c_entry = c_entry->next;
  }

  // Index not found, placing the new rule at the end
  last_entry->next = new_entry;
  new_entry->prev = last_entry;
}

/**
 * Find first matching rule with highest priority.
 */
fw_rule *find_matching_rule(fw_rule **head_ref, const uint8_t type,
                            const uint32_t ip_addr, const uint16_t port,
                            const char *p_name) {
  uint8_t highest_prio = MIN_PRIORITY;
  fw_rule *chosen_rule = NULL;

  fw_rule *curr_rule = (*head_ref);

  while (curr_rule != NULL) {
    if (((curr_rule->ip_start == 0 && curr_rule->ip_end == 0) ||
         (curr_rule->ip_start <= ip_addr && ip_addr <= curr_rule->ip_end)) &&
        (curr_rule->port == 0 || curr_rule->port == port) &&
        (curr_rule->type == 0 || curr_rule->type == type)) {
      // ip_addr is in this rules range
      if (curr_rule->p_name[0] != '\0') {
        // If function called with p_name and rule has a non-empty p_name, make
        // sure they match
        if (p_name != NULL &&
            strncmp(curr_rule->p_name, p_name, MAX_NAME_LEN) == 0) {
          if (curr_rule->priority >= highest_prio) {
            chosen_rule = curr_rule;
            highest_prio = curr_rule->priority;
          }
        }
      } else {
        // Rule has no p_name
        if (curr_rule->priority >= highest_prio) {
          chosen_rule = curr_rule;
          highest_prio = curr_rule->priority;
        }
      }
    }
    curr_rule = curr_rule->next;
  }

  return chosen_rule;
}

void get_ip_string(char *buf, uint32_t buf_len, uint32_t ip_addr) {
  unsigned char bytes[4] = {ip_addr & 0xFF, (ip_addr >> 8) & 0xFF,
                            (ip_addr >> 16) & 0xFF, (ip_addr >> 24) & 0xFF};
  snprintf(buf, buf_len, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/**
 * Print the named chain of rules.
 */
void print_rules(fw_rule **head_ref, const char *chain) {
  printf("Chain %s\n", chain);
  printf("%-5s%-8s%-9s%-16s%-16s%-6s%-16s\n", "type", "action", "priority",
         "start", "end", "port", "name");
  fw_rule *curr_rule = (*head_ref);
  while (curr_rule != NULL) {
    char action[7];
    char type_str[5];
    char start_ip_str[64];
    char end_ip_str[64];
    get_ip_string(start_ip_str, 64, curr_rule->ip_start);
    get_ip_string(end_ip_str, 64, curr_rule->ip_end);
    if (curr_rule->action == 1) {
      strncpy(action, "REJECT", 7);
    } else {
      strncpy(action, "ACCEPT", 7);
    }
    if (curr_rule->type == FW_TCP) {
      strncpy(type_str, "TCP", 5);
    } else if (curr_rule->type == FW_UDP) {
      strncpy(type_str, "UDP", 5);
    } else if (curr_rule->type == FW_ICMP) {
      strncpy(type_str, "ICMP", 5);
    } else if (curr_rule->type == FW_RAW) {
      strncpy(type_str, "RAW", 5);
    } else {
      strncpy(type_str, "IP", 5);
    }
    printf("%-5s%-8s%-9d%-16s%-16s%-6d%-16s\n", type_str, action,
           curr_rule->priority, start_ip_str, end_ip_str, curr_rule->port,
           curr_rule->p_name);
    curr_rule = curr_rule->next;
  }
  printf("\n");
  return;
}
/**
 * Insert a rule at the specified index of the chain.
 */
void insert_chain_rule(fw_chain *chain, int index, const uint32_t ip_start,
                       const uint32_t ip_end, const uint8_t type,
                       const uint16_t port, const uid_t uid,
                       const uint8_t action, const char *p_name,
                       const uint8_t direction) {
  // New rule and params
  fw_chain_rule *new_rule =
      (struct fw_chain_rule *)malloc(sizeof(fw_chain_rule));
  new_rule->type = type;
  new_rule->port = port;
  new_rule->user = uid;
  new_rule->ip_start = ip_start;
  new_rule->ip_end = ip_end;
  new_rule->action = action;
  new_rule->direction = direction;  // Package in or out]

  if (p_name != NULL) {
    strncpy(new_rule->p_name, p_name, MAX_NAME_LEN);
  } else {
    new_rule->p_name[0] = '\0';  // Empty string
  }

  // Find entries to modify. Add to chain entry linked list
  add_chain_rule(chain, new_rule, index);
}

/**
 * Push a rule to the start of the chain.
 */
void push_rule(fw_rule **head_ref, const uint32_t ip_start,
               const uint32_t ip_end, const uint8_t type, const uint16_t port,
               const uint8_t priority, const uint8_t action,
               const char *p_name) {
  fw_rule *new_node = (struct fw_rule *)malloc(sizeof(struct fw_rule));

  new_node->type = type;
  new_node->port = port;
  new_node->priority = priority;
  new_node->ip_start = ip_start;
  new_node->ip_end = ip_end;
  new_node->action = action;

  if (p_name != NULL) {
    strncpy(new_node->p_name, p_name, MAX_NAME_LEN);
  } else {
    new_node->p_name[0] = '\0';  // Empty string
  }

  new_node->next = (*head_ref);
  new_node->prev = NULL;
  if ((*head_ref) != NULL) {
    (*head_ref)->prev = new_node;
  }
  (*head_ref) = new_node;
}

/**
 * Remove the first rule that matches
 */
void remove_rule(fw_rule **head_ref, const uint32_t ip_start,
                 const uint32_t ip_end, const uint8_t type, const uint16_t port,
                 const uint8_t priority, const uint8_t action,
                 const char *p_name) {
  fw_rule *curr_rule = (*head_ref);
  while (curr_rule != NULL) {
    if (curr_rule->ip_start == ip_start && curr_rule->ip_end == ip_end &&
        curr_rule->action == action && curr_rule->type == type &&
        curr_rule->port == port) {
      if (curr_rule->p_name[0] != '\0') {
        if (p_name != NULL &&
            strncmp(curr_rule->p_name, p_name, MAX_NAME_LEN) == 0) {
          break;
        }
      } else {
        break;
      }
    }
    curr_rule = curr_rule->next;
  }

  if (curr_rule != NULL) {
    if (curr_rule->prev != NULL) {
      curr_rule->prev->next = curr_rule->next;
    } else {
      // Rule was the first of the list. Need to update head.
      (*head_ref) = curr_rule->next;
    }
    if (curr_rule->next != NULL) {
      curr_rule->next->prev = curr_rule->prev;
    }
    free(curr_rule);
  } else {
    printf("Did not find a matching rule to delete\n");
  }
  return;
}

#endif
