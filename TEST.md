# Manual Firewall Testing

## Installing and running

```sh
$ docker-compose up
```
```sh
$ sudo ./start.sh
```

OR

When the compilation is done you have to change the file ownership before starting the application
```sh
$ sudo chmod 777 minix_x86.img
```

Then you can start the OS
```sh
$ qemu-system-i386 --enable-kvm -L . -m 256M -drive file=minix_x86.img,if=ide,format=raw -serial stdio -curses
```

Start QEMU with internet access
```sh
$ qemu-system-i386 --enable-kvm -L . -m 256M -drive file=minix_x86.img,if=ide,format=raw -netdev user,id=mynet0 -device e1000,netdev=mynet0 -serial stdio -curses
```


## Setup Minix
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

## Brief description of the Firewall
The firewall uses 3 different chains with rules to check whether or not a packet
is allowd in or out. When a packet is going in or out from the system it will
traverse the chains in the following order:

1. Privileged chain
2. Global chain
3. User chain

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
$ ping -c 1 216.58.207.206
```

Now, let's add an ACCEPT rule to accept the packets going out to that IP address for all users.
You should see it written out by the ping command from the previous step. When
adding the new rule, make sure you are logged in as root.

In this example we will add the rule to the global chain without a user id. This way the rule will affect all users.

```sh
$ firewall -A 2 0 OUT ACCEPT 216.58.207.206
```

Now, check if you can ping `www.youtube.com`. You should be able to.

```sh
$ ping -c 1 216.58.207.206
```

### Per user rules

Delete the global rule created earlier (deletes at index 0, where it was added):

```sh
$ firewall -D 2 0
```

Now no user can access `www.youtube.com`

Make it possible for root to access. Must add to the privileged chain. 
```sh
$ firewall -A --user-id 0 1 0 OUT ACCEPT 216.58.207.206
```

The ping should now work.

```sh
$ ping -c 1 216.58.207.206
```

Add an unpriveliged user.

```sh
$ useradd foo
$ id foo
```

As root, make foo able to communicate to `www.youtube.com`. (our case: foo id = 1000) Add to the privileged chain.
```sh
$ firewall -A --user-id 1000 1 0 OUT ACCEPT 216.58.207.206
```

Foo is now able to ping `www.youtube.com`. If the previous command is not made (or removed), the ping would not be successful. 
```sh
$ su foo
$ ping -c 1 216.58.207.206
```

Foo cannot remove rules from the chains.


