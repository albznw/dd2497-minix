# Manual Firewall Testing

## Setup

Compile the code using releasetools and then run Minix using the command that releasetools generates for you. Add the flags for network access inside Minix.

```bash
./releasetools/x86_hdimage.sh
sudo qemu-system-i386 --enable-kvm -m 256 -hda minix_x86.img -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22
```

When you boot Minix, run the commands below to enable internet access.

```bash
netconf  # Just hit enter on all options that are presented
service network restart
```

You should now have the IP address *10.0.2.15* when you run `ifconfig`.

Try to ping using something like:

```bash
ping google.com
```

If it does not work you might have to this command on the HOST system (i.e. not in Minix)

```bash
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
```

## Testing

### Viewing Firewall rules

To view the currently active firewall rules run:

```bash
firewall -L
```

The `firewall` CLI is used to dynamically view, add and delete firewall rules.
For example:

```bash
firewall -A -t UDP -p 53 -n telnet OUT REJECT 0.0.0.0  # Add firewall rule that blocks telnets DNS resolution
firewall -L  # Look at the rule we just created
telnet -4 google.com 443  # Verify that firewall blocks name resolution
firewall -D -t UDP -p 53 -n telnet OUT REJECT 0.0.0.0  # Delete firewall rule we just created
telnet -4 google.com 443  # Verify that firewall no longer blocks
```

For more help with the CLI you can view the manual entry for `firewall` using:

```bash
man firewall
```

### Test 1 - Ping

One of the hardcoded default rules block outgoing IP packets to kth.se to test this:

```bash
ping google.com  # Should work
ping kth.se  # Should not work
```

### Test 2 - Process name using DNS lookups

One of the default rules should block outgoing UDP port 53 for the `dig` utility.
This means that if the rule applied to all other processes we can never resolve hostnames using UDP port 53.
Another default rule will override the first ruke and let `dig` resolve against Google DNS server at `8.8.8.8`. To test:

```bash
dig +short google.com  # Should not work
ping google.com  # First UDP port 53 packets that are the hostname lookup should work
dig +short google.com @8.8.8.8  # Should work since we have a rule with higher priority that overrides
```

### Test 3 - UDP and TCP

To verify that firewall can tell the difference between e.g. UDP and TCP:

```bash
telnet -4 google.com 443  # Should work
firewall -A -t UDP -p 443 -n telnet OUT REJECT 0.0.0.0  # Add rule to block UDP 443 (i.e. not TCP)
telnet -4 google.com 443  # Should still work
firewall -A -t TCP -p 443 -n telnet OUT REJECT 0.0.0.0  # Add rule to block TCP 443
telnet -4 google.com 443  # Now this should fail
```
