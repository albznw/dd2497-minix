# DD2497 System Security Rroject with Minix

### Participants

André Brogärd, brogard@kth.se  
Tommie Andersson, tommiean@kth.se  
Henrik Kultala, kultala@kth.se  
Albin Winkelmann, albinwi@kth.se  
Hîvron Stenhav, hivron@kth.se

## Run the application
To compile the application, it's recommended to use docker-compose. Navigate to the root directory and compile the operating system using

```sh
$ docker-compose up
```

When the compilation is done you have to change the file ownership before starting the application
```sh
$ sudo chmod 777 minix_x86.img
```

Then you can start the OS
```sh
$ qemu-system-i386 -L . -m 256M -drive file=minix_x86.img,if=ide,format=raw -serial stdio -curses
```
`-serial stdio` connects your terminal to the QEMU vm allowing you to use your own keyboard layout instead of being forced to use the english layout on QEMU.  
`-curses` starts the QEMU instance headlessly, allowing you to start the application from a server.  
### Project Specification
[Link to project specification PDF](Group5_Project_Specification.pdf)

### Docs
Used to aid us in our Firewall-developing-process.  
[docs](docs.md)  
[trello](https://trello.com/b/WNfCIHF4/project-board)

### Project Report
_To be written_
