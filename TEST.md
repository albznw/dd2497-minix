# Manual Firewall Testing

## Installing and running

```sh
docker-compose up
```
```sh
sudo ./start.sh
```

OR

When the compilation is done you have to change the file ownership before starting the application
```sh
sudo chmod 777 minix_x86.img
```

Then you can start Minix with internet access through QEMU:
```sh
qemu-system-i386 --enable-kvm -L . -m 256M -drive file=minix_x86.img,if=ide,format=raw -netdev user,id=mynet0 -device e1000,netdev=mynet0 -serial stdio
```
By suppling `-serial stdio` one is allowed to keep using the normal terminal, which one can paste text into. However, the QEMU window still opens, and some output appears in this window, so keep it visible as well. 

## Setup Minix
When you boot Minix, run the commands below to enable internet access.

```bash
netconf  # Just hit enter on all options that are presented
service network restart
```

You should now have the IP address *10.0.2.15* when you run `ifconfig`.

Try to ping KTH using:

```bash
ping -c 1 130.237.28.40
```

If it does not work you might have to this command on the HOST system (i.e. not in Minix)

```bash
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
```

## Brief description of the Firewall
The firewall uses 3 different chains with rules to check whether or not a packet
is allowd in or out. When a packet is going in or out from the system it will
traverse the chains in the following order:

1. Privileged chain (P)
2. Global chain (G)
3. User chain (U)

The firewall will first check the privileged- and the global chain for matching
rules. If no `ALLOW` or `REJECT` rules was found. The packet will simply be dropped
as the two together follows an whitelist approach.

If the packet was ALLOWED however the firewall will check the user chain as
well. This chain is here to allow users to further restrict programs to access
the internet. For example, a user might not want their downloaded python program
to access the internet. With this chain one can add `REJECT` rules and prevent
that from happening.

## Testing the Firewall

Start by pinging a network service, such as `www.youtube.com` (our case: 216.58.207.206) from your host machine, use that ip address below.

If we ping the service from minix. There is no rule to allow this communication. We should get a time out when doing:

```sh
ping -c 1 216.58.207.206
```

To list the rules of the global chain and confirm there is no rule allowing this connection we run the following command (you will see user ID 999 listed by each rule as this is currently the ID used to indicate no particular user):

```sh
firewall -L G
```

You should also confirm that there is no rule in the privileged chain for your user (you are currently user 0) that allows this:

```sh
firewall -L P
```

Now, let's add an ACCEPT rule to accept the packets going out to that IP address for all users.
You should see it printed out by the ping command from the previous step. When
adding the new rule, make sure you are logged in as root (user 0).

In this example we will add the rule to the global chain without a user id. This way the rule will affect all users.

```sh
firewall -A G 0 OUT ACCEPT 216.58.207.206
```

Now, check if you can ping `www.youtube.com`. You should be able to.

```sh
ping -c 1 216.58.207.206
```

### Per user rules

Delete the global rule created earlier (deletes at index 0, where it was added).

```sh
firewall -D G 0
```

Now no user can access `www.youtube.com`.

```sh
ping -c 1 216.58.207.206
```

To make it possible only for root to access, the rule must be added to the privileged chain. 

```sh
firewall -A -u 0 P 0 OUT ACCEPT 216.58.207.206
```

Print the privileged chain to see the new rule added:

```sh
firewall -L P
```

The ping should now work.

```sh
ping -c 1 216.58.207.206
```

Add an unpriveliged user and switch to it. Then try to ping again.

```sh
useradd foo
id foo
su foo
ping -c 1 216.58.207.206
```

This will not work since our previous rule was only for root.

As root, make foo able to communicate with `www.youtube.com`. Add to the privileged chain.

```sh
exit # If you're still logged in as "foo" you need to exit back to root
firewall -A -u 1000 P 0 OUT ACCEPT 216.58.207.206 # (in our case foo id = 1000)
```

Foo is now able to ping `www.youtube.com`.

```sh
su foo
ping -c 1 216.58.207.206
```

Foo may add rules to the user chain. In this case to restrict access.  

```sh
# While still logged in as foo
firewall -A U 0 OUT REJECT 216.58.207.206
```

Foo cannot ping `www.youtube.com` anymore. 

```sh
ping -c 1 216.58.207.206
```

However foo may not edit the privileged or global chain, trying to run any of these commands will have no effect:

```sh
# While still logged in as foo
firewall -A P 0 OUT ACCEPT 216.58.207.206
firewall -A G 0 OUT ACCEPT 216.58.207.206
```

Delete the user chain rule so that foo can ping again:

```sh
firewall -D U 0
ping -c 1 216.58.207.206
```

Exit back to root and create another user. Switch to this user and try to ping.
```sh
exit 
useradd bar
id bar
su bar
ping -c 1 216.58.207.206
```

This does not work since this user is different from foo, which has explicilty been allowed to ping. Exit back to root and add a rule allowing the ping in the global chain.

```sh
exit
firewall -A G 0 OUT ACCEPT 216.58.207.206
```

Now this connection is once again allowed for all users, even newly added ones:

```sh
su bar
ping -c 1 216.58.207.206
exit
useradd baz
id baz
su baz
ping -c 1 216.58.207.206
```