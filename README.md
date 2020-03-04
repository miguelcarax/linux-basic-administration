# Linux Administration Basics

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

**Managing software**
+ `rpm -qf /etc/httpd` - finds out which paquet the file belongs to  
+ `rpm -ql bash` - list what files does the package has installed

**Signals**
+ `man 7 signal` - overview of signals
+ `kill -s SIGTERM 5776`
+ `kill -15 1234`
+ `pkill python`
+ `pkill -u pablelas` + kill all `pablelas`' processes

**Processes**



**Man**
+ Man pages are stored in `/usr/share/man` and compressed in gzip format. `man` is able to decompress it on the fly

**Monitoring Network**

**Managing users**
+ `su - julian` - Impersonate as `julian` user. `-` option will provoke to act if it was a user login
+ `/etc/sudoers` - `pablelas ALL = ( ALL : ALL) NOPASSWD: ALL` - Full `root` access to `pablelas` user
+ `passwd -l` - locks an account by prepending a ! to the encrypted password (`/etc/shadow`)
+ shells should be set to `/bin/false` or `/bin/nologin` to protect against remote login

**Filesystems and System Tree Layout**
+ `man hier` - information about tipical linux directories `var`, `etc`, `usr`, etc.
+ `mount -o nosuid /dev/sda1 /home/alonso` - mount `/dev/sda1` filesystem without allowing using `setuid` executables in it.
+ `mount` - list mounted filesystems
+ `man proc` - shows `/proc` filesystem information
+ `umount -l /home/alonso` - umount filesystem lazily, when opened files are closed
+ `fuser -vc /home/alonso` - list information of processes who have opened files in the filesystem mountpoint
+ `file /bin/ping` - determine file type
+ `ln -s <src> <dest>` - remember the same syntax as `cp` command
+ _search_ or _scan_ bit allows the directory to be entered or passed through as a pathname is evaluated,
but not to have its contents listed
+ The bits with octal values `4000` and `2000` are the setuid and setgid bits.
+ When set on a directory, the `setgid` bit causes newly created files within the directory to take on the group ownership of the directory rather than the default group of the user that created the file
+ If the sticky bit (`1000`) is set on a directory, the filesystem won’t allow you to delete or rename
a file unless you are the owner of the directory, the owner of the file, or the
superuse
+ `ls -li` - list files on current directory including _inode_ number.
+ `ls -lrsta /tmp` - list all files in `/tmp` sorted ascended by modification time
+ `ls -F dir` - show files distingishing between kinds of files 
+ `chmod ug=rw,o=r file` - fives r/w permission to owner and group, and read permission to others
+ `chmod a-x file` - removes execute permission for all categories (owner/group/other)
+ `chmod --reference=filea fileb` - makes fileb’s mode the same as filea’s
+ `find mydir -type f -exec chmod a-x {} ';'` - change permissions only to _files_ rather than both _files_ and _dirs_.
+ `chown user1:group1 -R dir` - change recursively owner and group of all files within `dir`
+ `umask 0222` - set the octal permission to *remove* from the new created files. It will do a NAND operation with default creation permissions
+ `umask 027` - denie all permission from _others_ and write permission for _group_ to all new created files.
+ `umask` only applies to current session.
+ `chattr` - change file attributes
+ `lsattr` - list file attributes
+ `setfacl -m user:julian:rwx file` - allow `julian` user to read, write, execute via ACL permissions.
+ `setfacl -m default:group:datascientist:r-x dir` -  set default ACLs por group `datascientist` in `dir`
+ `setfacl -R -x other::rwx dir` - remove `rwx` permission from `others` in `dir` recursively.
+ `setfacl -m default:mask:0222 dir` - set default `mask` for `dir`. This `mask` is an AND operation rather than the NAND operation of `umask` command.
+ entries for named users, named groups, and the default group can include permission bits that are not present in the mask, but filesystems simply ignore them.
+ `setfacl-n` option to prevent setfacl from regenerate the `mask` when modifying current ACLs
+ `getfacl file` - list `file` ACLs


**Monitoring Processes**
+ `/proc/cmdline` - show with which options was the kernel launched
+ `ps xawf -eo pid,user,cgroup,args` - Monitor which process belong to which cgroup
+ `ps -fx` - processes owned by you
+ `ps -fU user -C command` - processed runned by `user` with `command` in execution command
+ `ps -fp 2226,1154,1146` - procssed with pid `x`
+ `ps --forest -e` - show processes in a tree view form
+ `ps -p 1223 -o pid,ppid,fgroup,ni,lstart,etime,cgroup` - custom process output
+ `ps -x -o pid=` - print all processes PID owned by you in a _quiet_ form
+ `ps -ef --sort +pid` - list all system processes sorted by ascend PID
+ `top` - provides  a  dynamic real-time view of a running system
+ `ps` and `top` read from `/proc`
+ `/usr/bin/nice -n5 date` - launch `date` command with 5 points increased _niceness_
+ `sudo /usr/bin/renice -n -10 24247` - renice process `24247` to -10 priority
+ `/proc/<pid>/maps` -  show what libraries the process depends on
+ `/proc/<pid>/fd` - file descriptors opened by the process. Can contain symlinks to real files
+ `strace` - shows system calls trace from a process
+ `crontab -e` - edit user crontab file
+ `crontab -l` - list user crontabs
+ `minute hour dom month weekday command` - crontab line format
+ `20 1 * * * find /tmp -mtime +7 -type f -exec rm -f { } ';'` - crontab, it removes all files in the `/tmp` directory
that have not been modified in 7 days.
+ `systemd` defines `timers` that like `cron` execute a system process on a predefined schedule. More info in `man systemd.timer`

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
