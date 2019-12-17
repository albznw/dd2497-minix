/*
 * fwdec - Firewall decision server
 * Author: Thomas Peterson
 */

#include "inc.h"
#include "fwdec.h"

#include "rule.h"

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
static void log(char* log_message);

static IPRule* out_rules = NULL;
static IPRule* in_rules = NULL;

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
  // Push default rules
  push_rule(&out_rules, IP_ANY, IP_ANY, MIN_PRIORITY, FW_RULE_ACCEPT, NULL);
  push_rule(&in_rules, IP_ANY, IP_ANY, MIN_PRIORITY, FW_RULE_ACCEPT, NULL);

  // Push custom hard-coded rules
  uint32_t kth_ip = ip4_from_parts(130, 237, 28, 40);
  uint32_t google_dns = ip4_from_parts(8, 8, 8, 8);
  push_rule(&out_rules, kth_ip, kth_ip, MAX_PRIORITY, FW_RULE_REJECT, NULL);
  push_rule(&out_rules, google_dns, google_dns, MAX_PRIORITY, FW_RULE_ACCEPT, "dig");
  push_rule(&out_rules, IP_ANY, IP_ANY, MED_PRIORITY, FW_RULE_REJECT, "dig");

  printf("Firewall decision server started\n");
  return(OK);
}

/*===========================================================================*
 *				do_publish				                                     *
 *===========================================================================*/

int check_incoming_ip4(uint32_t src_ip) {
  return LWIP_KEEP_PACKET;
}

int check_outgoing_ip4(uint32_t dest_ip, const char *p_name) {
  // Change NULL to incoming pname
  IPRule *matched_rule = find_matching_rule(&out_rules, dest_ip, p_name);

  if (matched_rule->action == FW_RULE_REJECT) {
    log("Packet dropped\n");
    return LWIP_DROP_PACKET;
  }

  log("Packet accepted\n");
  return LWIP_KEEP_PACKET; 
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
