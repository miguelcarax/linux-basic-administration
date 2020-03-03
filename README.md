**BASH**
+ `compgen -c` - list all system binaries in `$PATH`
+ `/etc/profile` - executed automatically at login
+ `/home/user/.bashrc`  - is read by every nonlogin shell
+ `~+` - current working directory (`$PWD`)
+ `$_` - final argument in last executed command
+ `sudo !!` - executes last command as sudo
+ `bash` reads `~/.bash_profile` in login mode and `~/.bashrc` in nonlogin mode

+ `whereis` - locate the binary, source, and manual page files for a command
+ `locate` -  find files by name

+ **Managing software**
+ `rpm -qf /etc/httpd` - finds out which paquet the file belongs to  
+ `rpm -ql bash` - list what files does the package has installed


**Man**
+ Man pages are stored in `/usr/share/man` and compressed in gzip format. `man` is able to decompress it on the fly

**Monitoring Network**

**Managing users**
+ `su - julian` - Impersonate as `julian` user. `-` option will provoke to act if it was a user login
+ `/etc/sudoers` - `pablelas ALL = ( ALL : ALL) NOPASSWD: ALL` - Full `root` access to `pablelas` user
+ `passwd -l` - locks an account by prepending a ! to the encrypted password (`/etc/shadow`)
+ shells should be set to `/bin/false` or `/bin/nologin` to protect against remote login

**Filesystems**
+ `mount -o nosuid /dev/sda1 /home/alonso` - mount `/dev/sda1` filesystem without allowing using `setuid` executables in it.


**Monitoring Processes**
+ `/proc` - The proc filesystem is a pseudo-filesystem which provides an interface to kernel data structures. Look `man proc`
+ `/proc/cmdline` - show with which options was the kernel launched
+ `ps xawf -eo pid,user,cgroup,args` - Monitor which process belong to which cgroup
+ `ps -fx` - processes owned by you
+ `ps -fU user -C command` - processed runned by `user` with `command` in execution command
+ `ps -fp 2226,1154,1146` - procssed with pid `x`
+ `ps --forest -e` - show processes in a tree view form
+ `ps -p 1223 -o pid,ppid,fgroup,ni,lstart,etime,cgroup` - custom process output
+ `ps -x -o pid=` - print all processes PID owned by you in a _quiet_ form
+ `top` - provides  a  dynamic real-time view of a running system

**System Startup and Shutdown**
+ `/etc/sysconfig/*` - are used when starting, stopping, configuring or querying system services (Red Hat)
+ `/etc/default/*` - same as `sysconfig` but related to Debian
+ `shutdown -h +5` -  halt system in 5 minutes
+ `shutdown -r now` - restart system now
+ Kernel options on problems - `init=/bin/bash`

**GRUB**
+ `grub2-mkconfig`
 + `/etc/default/grub`
 + `/etc/grub.d/40-custom`
+ `grubby` - grubby - command line tool used to configure bootloader 
+ `grub2-install /dev/sda ` - Install grub on disk
+ `dracut` - create initial ramdisk images for preloading modules
+ `/boot` - stores data used before the kernel begins executing user-mode programs
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
+ `systemctl list-dependencies rescue.target` - list all units involved in `rescue.target`
+ `systemctl enable sshd.service --now` - enable and start `sshd`
+ `systemctl set-default multi-user.target` - change the default run level in the system
+ `systemctl is-active docker.service`
+ `systemctl isolate rescue.target` - Change execution mode to `rescue.target`
+ `systemctl daemon-reload docker.service` - Reloads when a new service is created or any configuration is modified.
+ `systemctl reboot` - same as `systemctl start reboot.target --irreversible`
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
