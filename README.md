**misc**
+ `compgen -c` - list all system binaries (`$PATH`)
+ `/proc/cmdline` - show with which options was the kernel launched


**Chapter 2 - Linux Filesystem Tree Layout**
+ `/boot` - stores data used before the kernel begins executing user-mode programs
+ `/boot/vmlinuz-4.15.0-50-generic` - Linux kernel
+ `/boot/initramfs-3.10.0-514.el7.x86_64.img` - Initial RAM filesysmte
+ ``

**Chapter 3 - Processes**
+ `/proc` - The proc filesystem is a pseudo-filesystem which provides an interface to kernel data structures. Look `man proc`
+ 

**Chapter X - Monitoring processes"
+ `ps xawf -eo pid,user,cgroup,args` - Monitor which process belong to which cgroup

**Chapter 37 - System Startup and Shutdown**
+ `/etc/sysconfig/*` - are used when starting, stopping, configuring or querying system services (Red Hat)
+ `/etc/default/*` - same as `sysconfig` but related to Debian
+ `shutdown -h +5` -  halt system in 5 minutes
+ `shutdown -r now` - restart system now

**Chapter 38 - GRUB**
+ `grubby` - auto-generate `/boot/grub/grub.conf` (also do this `grub2-mkconfig`) based on
	+ `/etc/grub.d`
	+ `/etc/default/grub`
+ `grub2-install /dev/sda ` - Install grub on disk
+ `dracut` - create initial ramdisk images for preloading modules
+ `/boot/vmlinuz-4.14.72-68.55.amzn1.x86_64` - Linux kernel compressed (`cpio`) file
+ `/boot/initramfs-4.14.72-68.55.amzn1.x86_64.img` - `initramfs` file for kernel

**Chapter 39 - System Init: systemd, System V and Upstart**
+ `man bootup` - information about startup process
+ `/etc/vconsole.conf` -  default keyboard mapping and console font.
+ `/etc/sysctl.d/*.conf` - drop-in directory for kernel sysctl parameters.
+ `/etc/systemd/system/*.target.wants/*.service` - where different systemd targets (like runlevels) units files are located
+ `systemd-cgls` - systemd cgroups info
+ `man systemd.special` - describe basic systemd units
+ `man systemd.service` - Service unit configuration
+ `systemctl start /path/to/foo.service`
+ `systemctl` - how the status of everything that systemd controls
+ `systemctl cat docker` - cat the `docker.service` unit file
+ `systemctl list-units -t service --all`
+ `systemctl list-units -t service` - list active units
+ `systemctl list-unit-files --type=service` - list installed units
+ `systemctl enable sshd.service --now` - enable and start `sshd`
+ `systemctl set-default multi-user.target` - change the default run level in the system
+ `systemctl is-active docker.service`
+ `systemctl daemon-reload docker.service` - Reloads when a new service is created or any configuration is modified.
 + Unit files stored in `/etc/systemd/`system override those from `/lib/systemd/system`
+ `/etc/systemd/system/docker.service.d/http-proxy.conf` - unit additional configuration file
+ `systemd-analyze` - get info about systemd startup time
+ `/run/systemd` - systemd places its local communications sockets
+ `/sbin/telinit 5` - change the runlevel of the system
+ `/etc/inittab` - determines which level should be the system run
+ `/etc/rc.d/rc.sysinit` - first runned script in System V systems.
+ `/etc/rc.d/rc[0-6].d` - runlevel(s) scripts
+ `/etc/init.d` - all scripts involucred in `rc[0-6].d` runlevels, they are simlinks to `rc[0-6].d`
+ `/etc/rc3.d/S09mk-tmp-on-root -> /etc/init.d/mk-tmp-on-root`
+ `chkconfig ` -  is used to query and configure what runlevels the various system services are to run in System V systems.
+ `service puppet restart` - like `systemctl` for System V systems
+ `localectl` - control the system locale and keyboard layout settings
+ `hostnamectl` - control the system hostname
+ `timedatectl` - control the system time and date
+ `loginctl` - control the systemd login manager
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``
+ ``

** Biografía **
+ Rethinking PID 1 - http://0pointer.de/blog/projects/systemd.html
+ Systemd webpage - https://www.freedesktop.org/wiki/Software/systemd/
+ ¿What is the purpose of the `initramfs` file?  - https://wiki.gentoo.org/wiki/Initramfs/Guide
