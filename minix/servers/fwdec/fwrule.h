#ifndef _FWDEC_RULE_H_
#define _FWDEC_RULE_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_PRIORITY 0xFF
#define MED_PRIORITY 0xAA
#define MIN_PRIORITY 0x00

#define MAX_NAME_LEN 16

/**
 * Let fw_rules be a doubly linked list that exists on the HEAP.
 */
typedef struct fw_rule {
    uint8_t priority;
    uint8_t action;
    uint32_t ip_start;
    uint32_t ip_end;
    char p_name[MAX_NAME_LEN];
    struct fw_rule* next;
    struct fw_rule* prev;
} fw_rule;

/**
 * Find first matching rule with highest priority.
 */
fw_rule *find_matching_rule(fw_rule** head_ref, const uint32_t ip_addr, const char *p_name) {

    uint8_t highest_prio = MIN_PRIORITY;
    fw_rule *chosen_rule = NULL;

    fw_rule *curr_rule = (*head_ref);

    while (curr_rule != NULL){
        if ((curr_rule->ip_start == 0 && curr_rule->ip_end == 0)
            || (curr_rule->ip_start <= ip_addr && ip_addr <= curr_rule->ip_end)) {

            // ip_addr is in this rules range
            if(curr_rule->p_name[0] != '\0'){
                // If function called with p_name and rule has a non-empty p_name, make sure they match
                if(p_name != NULL && strncmp(curr_rule->p_name, p_name, MAX_NAME_LEN) == 0){
                    if(curr_rule->priority >= highest_prio) {
                        chosen_rule = curr_rule;
                        highest_prio = curr_rule->priority;
                    }
                }
            } else {
                // Rule has no p_name
                if(curr_rule->priority >= highest_prio) {
                    chosen_rule = curr_rule;
                    highest_prio = curr_rule->priority;
                }
            }
        }
        curr_rule = curr_rule->next;
    }

    return chosen_rule;
}

/**
 * Push a rule to the start of the chain.
 */
void push_rule(fw_rule** head_ref, const uint32_t ip_start, const uint32_t ip_end, const uint8_t priority,
                  const uint8_t action, const char* p_name) {

    fw_rule* new_node = (struct fw_rule*)malloc(sizeof(struct fw_rule));

    new_node->priority = priority;
    new_node->ip_start = ip_start;
    new_node->ip_end = ip_end;
    new_node->action = action;

    if(p_name != NULL) {
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
void remove_rule(fw_rule** head_ref, const uint32_t ip_start, const uint32_t ip_end, const uint8_t priority,
                    const uint8_t action, const char* p_name) {

    fw_rule *curr_rule = (*head_ref);
    while (curr_rule != NULL){
        if (curr_rule->ip_start == ip_start && curr_rule->ip_end == ip_end && curr_rule->action == action) {
            if(p_name != NULL){
                if(strncmp(curr_rule->p_name, p_name, MAX_NAME_LEN) == 0){
                    break;
                }
            } else {
                break;
            }
        }
        curr_rule = curr_rule->next;
    }

    if(curr_rule != NULL) {
        if(curr_rule->prev != NULL){
            curr_rule->prev->next = curr_rule->next;
        }
        if(curr_rule->next != NULL){
            curr_rule->next->prev = curr_rule->prev;
        }
        free(curr_rule);
    }
    return;
}

#endif
