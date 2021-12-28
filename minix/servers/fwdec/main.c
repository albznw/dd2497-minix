#include <minix/endpoint.h>

#include "inc.h" /* include master header file */

/* Allocate space for the global variables. */
static endpoint_t who_e; /* caller's proc number */
static int callnr;       /* system call number */

/* Message parameters */
static char proc_name[16];
static uint32_t src_ip;
static uint32_t dest_ip;
static uint16_t src_port;
static uint16_t dest_port;
static uint64_t flags;

/* Declare local functions. */
static void get_work(message *m_ptr);
static void reply(endpoint_t whom, message *m_ptr);

/* SEF functions and variables. */
static void sef_local_startup(void);

/*===========================================================================*
 *				main                                         *
 *===========================================================================*/
int main(int argc, char **argv) {
  /* This is the main routine of this service. The main loop consists of
 * three major activities: getting new work, processing the work, and
 * sending the reply. The loop never terminates, unless a panic occurs.
 */

  printf("fwdec: start - main\n\r");
  message m;
  int result;

  int effuid = UID_ANY;

  /* SEF local startup. */
  env_setargs(argc, argv);
  sef_local_startup();

  /* Main loop - get work and do it, forever. */
  while (TRUE) {
    /* Wait for incoming message, sets 'callnr' and 'who'. */
    get_work(&m);

    if (is_notify(callnr)) {
      printf("fwdec: warning, got illegal notify from: %d\n", m.m_source);
      result = EINVAL;
      goto send_reply;
    }

    switch (callnr) {
      case FWDEC_ADD_RULE:
        result = add_rule(m.m_fwdec_rule.direction, m.m_fwdec_rule.type, m.m_fwdec_rule.action,
                          m.m_fwdec_rule.ip_start, m.m_fwdec_rule.ip_end, m.m_fwdec_rule.port, m.m_fwdec_rule.p_name,
                          m.m_fwdec_rule.chain_id, m.m_fwdec_rule.index, m.m_fwdec_rule.uid);
        break;
      case FWDEC_DEL_RULE:
        result = delete_rule(m.m_fwdec_rule.chain_id, m.m_fwdec_rule.index);
        break;
      case FWDEC_LIST_RULES:
        list_rules(m.m_fwdec_rule.chain_id);
        result = OK;
        break;
      default:
        if (m.m_fwdec_ip4.user_endp) {
          // Get process name and effective user ID
          getepname(m.m_fwdec_ip4.user_endp, proc_name, 16);
          getepeffuid(m.m_fwdec_ip4.user_endp, &effuid);
        }
        src_ip = m.m_fwdec_ip4.src_ip;
        dest_ip = m.m_fwdec_ip4.dest_ip;
        src_port = m.m_fwdec_ip4.src_port;
        dest_port = m.m_fwdec_ip4.dest_port;
        flags = m.m_fwdec_ip4.flags;
        result = check_packet(callnr, src_ip, dest_ip, src_port, dest_port, (char *)proc_name, flags, effuid);
        break;
    }

  send_reply:
    memset(&m, 0, sizeof(m));
    /* Finally send reply message, unless disabled. */
    if (result != EDONTREPLY) {
      m.m_type = result; /* build reply message */
      reply(who_e, &m);  /* send it away */
    }
  }
  return (OK); /* shouldn't come here */
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void sef_local_startup() {
  /* Register init callbacks. */
  sef_setcb_init_fresh(sef_cb_init_fresh);
  sef_setcb_init_restart(sef_cb_init_fresh);

  /* Let SEF perform startup. */
  sef_startup();
}

/*===========================================================================*
 *				get_work                                     *
 *===========================================================================*/
static void get_work(
    message *m_ptr /* message buffer */
) {
  int status = sef_receive(ANY, m_ptr); /* blocks until message arrives */
  if (OK != status)
    panic("failed to receive message!: %d", status);
  who_e = m_ptr->m_source; /* message arrived! set sender */
  callnr = m_ptr->m_type;  /* set function call number */
}

/*===========================================================================*
 *				reply					     *
 *===========================================================================*/
static void reply(
    endpoint_t who_e, /* destination */
    message *m_ptr    /* message buffer */
) {
  int s = ipc_send(who_e, m_ptr); /* send the message */
  if (OK != s)
    printf("fwdec: unable to send reply to %d: %d\n", who_e, s);
}
