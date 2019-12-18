/*
 * fwdec - Firewall decision server
 * Author: Thomas Peterson
 */

#include "inc.h"
#include "fwdec.h"
#include <minix/com.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h> //File handling
#include <fcntl.h> //File handling flags
#include <sys/time.h> //System time

/* Declare local functions. */
static fw_rule_t *find_matching_rule(fw_rule_t *rules, uint32_t ip_addr, const char *p_name);
static void log(char* log_message);

static fw_rule_t default_incoming_rule = {
  .ip_start = IP_ANY,
  .ip_end = IP_ANY,
  .p_name = NULL,
  .action = FW_RULE_ACCEPT,
  .next = NULL,
};

static fw_rule_t default_outgoing_rule = {
  .ip_start = IP_ANY,
  .ip_end = IP_ANY,
  .p_name = NULL,
  .action = FW_RULE_ACCEPT,
  .next = NULL,
};

static inline uint32_t ip4_from_parts(uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4)
{
  uint32_t result = p4 << 24 | p3 << 16 | p2 << 8 | p1;
  return result;
}

/* Global variables - Configurables */
const char *LOGFILE = "/var/log/fwdec"; //Where the log file should be placed

/*===========================================================================*
 *		            sef_cb_init_fresh                                        *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  printf("Firewall decision server started\n");
  return(OK);
}

/*===========================================================================*
 *				do_publish				                                     *
 *===========================================================================*/

int check_incoming_ip4(uint32_t src_ip) {
  return LWIP_KEEP_PACKET;
}

int check_outgoing_ip4(uint32_t dest_ip) {
  fw_rule_t *rules = &default_outgoing_rule;
  uint32_t kth_ip = ip4_from_parts(130, 237, 28, 40);

  fw_rule_t kth_rule = {
    .ip_start = kth_ip,
    .ip_end = kth_ip,
    .action = FW_RULE_REJECT,
    .next = rules,
    .p_name = NULL
  };

  rules = &kth_rule;
  // Change NULL to incoming pname
  fw_rule_t *matched_rule = find_matching_rule(rules, dest_ip, NULL);

  if (matched_rule->action == FW_RULE_REJECT) {
    log("Packet dropped\n");
    return LWIP_DROP_PACKET;
  }

  log("Packet accepted\n");
  return LWIP_KEEP_PACKET; 
}

static fw_rule_t *find_matching_rule(fw_rule_t *rules, uint32_t ip_addr, const char *p_name)
{
  fw_rule_t *curr_rule = rules;
  fw_rule_t *chosen_rule = NULL;
  uint8_t chosen_flags = 0;
  bool name_match = false;

  while (curr_rule != NULL) {
    uint8_t curr_flags = 0;

    if (curr_rule->ip_start == 0 && curr_rule->ip_end == 0) {
      curr_flags |= FW_FLAG_ANY_IP;
    }

    if (curr_rule->ip_start <= ip_addr && ip_addr <= curr_rule->ip_end) {
      curr_flags |= FW_FLAG_IP_IN_RANGE;
    }

    if (curr_rule->ip_start == ip_addr && ip_addr == curr_rule->ip_end) {
      curr_flags |= FW_FLAG_EXACT_IP;
    }

    if (p_name == NULL && !name_match && curr_flags > chosen_flags) {
      chosen_rule = curr_rule;
      chosen_flags = curr_flags;
    } else if (p_name != NULL && strcmp(p_name, curr_rule->p_name) == 0 && !name_match && curr_flags > 0) {
      chosen_rule = curr_rule;
      chosen_flags = curr_flags;
      name_match = true;
    } else if (p_name != NULL && strcmp(p_name, curr_rule->p_name) == 0 && name_match && curr_flags > chosen_flags) {
      chosen_rule = curr_rule;
      chosen_flags = curr_flags;
    }
    
    curr_rule = curr_rule->next;
  }

  return chosen_rule;
}

static void log(char* log_message)
{
  // strncat(log_message, "\n", 1);
  int fd = open(LOGFILE, O_WRONLY|O_CREAT|O_APPEND);

  if (fd == -1){
    printf("Warning: fwdec failed to open log file %s\n", LOGFILE);
    return;
  }

  int length = strlen(log_message);
  int written = write(fd, log_message, length);
  if (written != length){
    printf("Warning: fwdec failed to write to log file");
  }
  close(fd);
}
