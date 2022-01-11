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