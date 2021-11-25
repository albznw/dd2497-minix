# Docs

André har fantastiskt minne, fråga honom.

## Firewall
Looks like all TCP Firewall logic is happening here in [fwdec_query_packet](https://github.com/albznw/dd2497-minix/blob/78888bf0f764bf22c0905a4053efe155e457f94d/minix/minix/lib/libsys/fwdec.c)

Here's where the processor name is fetched [main.c](https://github.com/albznw/dd2497-minix/blob/78888bf0f764bf22c0905a4053efe155e457f94d/minix/minix/servers/fwdec/main.c).

## Changes
* What we actually want to do is replace their firewall decision function with our own. Effectively making the firewall act on chains instead of rules. Kinda the same thing but without priority and we are going to add the ability to define user __and__ process specific rules.

### Changes in files
* Add PID to mess_fwdec_rule [here](https://github.com/albznw/dd2497-minix/blob/78888bf0f764bf22c0905a4053efe155e457f94d/minix/minix/include/minix/ipc.h#L238)
* Our logic should be added in [fwdec.c](https://github.com/albznw/dd2497-minix/blob/78888bf0f764bf22c0905a4053efe155e457f94d/minix/minix/servers/fwdec/fwdec.c) in servers folder.
