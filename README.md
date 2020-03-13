# Linux Administration Basics

**BASH**

+ `/etc/environment` is the first file loaded by `bash` shell
+ `compgen -c` - list all system binaries in `$PATH`
+ `~+` - current working directory (`$PWD`)
+ `$_` - final argument in last executed command
+ `sudo !!` - executes last command as sudo
+ `bash` reads `~/.bash_profile` in login mode and `~/.bashrc` in nonlogin mode
+ `uname -v` - print kernel version
+ `whereis date` - locate the binary, source, and manual page files for a command
+ `whatis date` - one-line information about the command
+ `whoami` -  print effective userid
+ `locate` -  find files by name
+ `env` - print environment and shell variables in current sesion
+ `printenv SHELL` - print `SHELL` var value
+ `!88` - execute command `88` in shell history
+ `type` - Indicate how a command name is interpreted
+ `ls -1 [[:upper:]]*` - print all files which start with an upper case letter
+ `touch file{001..5}` - create `file001`, `file002` and `file003`
+ `touch {A{1,2},B{3,4}}b` - create `aA1b`, `aA2b`, `aB3b`, `aB4b`
+ `mkdir {2007..2009}-{01..12}`
+ _By default, word splitting looks for the presence of spaces, tabs, and newlines (line feed characters) and treats them as delimiters between words. This means unquoted spaces, tabs, and newlines are not considered to be part of the text_
+ files loaded in login shells - `/etc/profile` and `~/.bash_profile` (usually `~/.bashrc` too)
+ files loaded in non-login shells - `~/.bashrc`
+ `aliases` and exported `variables` are inhereited by sub-shells

**Managing software**
+ `rpm -qf /etc/httpd` - finds out which paquet the file belongs to  
+ `rpm -ql bash` - list what files does the package has installed
+ `rpm -U iperf` - upgrade `iperf` package

**Signals**
+ `man 7 signal` - overview of signals
+ `kill -s SIGTERM 5776`
+ `killall -u USER` - kill all `USER` processes
+ `kill -15 1234`
+ `pkill python`
+ `pkill -u pablelas` + kill all `pablelas`' processes

**Man**
+ Man pages are stored in `/usr/share/man` and compressed in gzip format. `man` is able to decompress it on the fly
+ `man man`
+ `man -k keyword` - let's you find _commands_ based on `keyword`

**Monitoring Network**

**Managing users**
+ `/etc/passwd` - is a list of users recognized by the system.
+ `su - julian` - Impersonate as `julian` user. `-` option will provoke to act if it was a user login loading `julian` environment variables and changing to `julian` home dir
+ `/etc/sudoers` - `pablelas ALL = ( ALL : ALL) NOPASSWD: ALL` - Full `root` access to `pablelas` user
+ Most distributions establish a different path for finding executables for normal users as compared to root users. In particular the directories `/sbin` and `/usr/sbin` are not searched, since `sudo` inherits the `PATH` of the user, not the full root user
+ `passwd -l` - locks an account by prepending a ! to the encrypted password (`/etc/shadow`)
+ shells should be set to `/bin/false` or `/bin/nologin` to protect against remote login
+ `authconfig --passalgo=sha512 --update` - change the algorith to cypher the user password stored in `/etc/shadow`
+ `chage -d 0 username` - invalidate user password and force update
+ `passwd -d usename` - invalidate user password and force update
+ `passwd -S miguelones` - get info about `miguelones` password
+ `echo password | passwd --stdin username` - pass the `username` `password` to `passwd` from `stdin` pipe
+ An `INACTIVE` account may not login
+ `chsh -s /bin/zsh username` - change `username` default shell
+ `usermod -e 2020-01-01 username` - disable `username` user account at the date supplied
+ `/etc/profile` - system wide user configuration file. Read by `bash` and `sh`
+ `/etc/profile.d/example.sh` - Same as above
+ `/etc/login.defs` and `/etc/default/useradd` - default options for `useradd` command
+ `useradd -D -s /bin/bash` - set `bash` as default shell for all new created users, modify `/etc/default/useradd` file
+ `useradd -c "David Hilbert" -d /home/math/hilbert -g hilbert -G faculty -m -s /bin/tcsh hilbert`
+ `gpasswd --delete miguelones sudo` - remove `miguelones` user from `sudo` group
+ `find filesystem -xdev -nouser` - check for orphaned files after a user has been removed
+ `usermod -L username` - lock `username` account, this disables login. 
+ `usermod -aG docker miguelones` - add `miguelones` user to `docker` group
+ `chsh -s /bin/nologin username` -  disables `username` user to login
+ `w` - shows you who is currently loged-in
+ `who` - show who is logged on
+ `loginctl list-sessions` - list current system sessions
+ `loginctl session-status 14` - get all information about session `14`

**Managing files**
+ `file` - determine file type
+ `dd if=/dev/zero of=/tmp/file bs=1M count=100` - create a file with _zeros_ with size `1MB` * `100`
+ `tar -cf file.bzip2 --bzip file` - create a `bzip2` tarball
+ `tar -czf file.tar.gz file` - create a `gzip` tarball
+ `tar -tvf file.tar.gz` - list the content of the tarball `file.tar.gz`
+ `tar -xzvf file.tar.gz` - untar `file.tar.gz` tarball
+ `tar -cf file.tar.xz --xz file` - create a `xz` tarball
+ `tar -xf file.tar -C /tmp/dir` - untar `file.tar` in `/tmp/dir`
+ `tar -cjf tarball-content.tar.bz tarball-content.tar` - further compress a `tar` file with `bzip2` compress
+ `gzip` for compress and `gunzip` for decompress
+ `find ~ -type f -name 'foo*' -exec ls -l '{}' +` - the `+` indicates that all founds possibilities will be passed to the `ls` command rather than executing `ls` for each ocurrence
+ `find /etc -type f -exec grep -l miguel '{}' \; -exec cp '{}' /tmp \;` - concatenate 2 `-exec` for the same found files
+ `find /etc/ -type f -exec grep -l "127.0.0.1" "{}" "+"`
+ `sed [address] operation [options]` - `sed` command syntax
+ `sed '' file` - same as `cat file`
+ `sed -n '1,5p' file` - print from line `1` to line `5`
+ `sed -n '1,+4p' file` - print from line `1` to line `1+4`
+ `sed -n '1,$p' file` - print from line `1` to the last line (`$`)
+ `sed -n '1~2p' file` - print line `1`, `3`, `5`, `7`, etc
+ `sed -n '1,3,8,12p' file` - print line `1`, `3`, `8` y `12` 
+ `sed '1d;$d' file` - delete the first and the last line
+ `sed '1!d' file` - delete all lines but the first
+ `sed -n '/^$/!p'` - print all non-blank lines
+ `sed '/^[[:upper:]]/d'` - delete all lines starting with uppercase letters
+ `sed 's/[[:alpha:]]\+/"&"/g' file` - put every word within double quotes
+ `sed 's/^.*$/&;/g' file` - put a `;` at the end of all lines
+ `sed G file` - put a empty line between every line and the next one
+ `sed 's:abc:def:g' file` is the same as `sed 's/abc/def/g' file` as  `sed 's|abc|def|g' file`
+ `sed 's/\([a-z]*\).*/\1/' file` - keep the first ocurrence (`\1`) of `[a-z]*` and delete the rest of the line content
+ `sed '/^#/ !s/.*/#&/g' file` - comment all lines `#` that are not already commented
+ `sed '$r file1' file2` - concatenate the content `file1` at the end of `file2`
+ `grep -w alex file` - will match lines with `alex` word but not `alexander`
+ `grep -C1 username file` - print the line(s) matched, the above one, and the below one
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
+ `dir` default permissions is `777`, file default permission is `666`
+ `chmod ug=rw,o=r file` - fives r/w permission to owner and group, and read permission to others
+ `chmod a-x file` - removes execute permission for all categories (owner/group/other)
+ `chmod --reference=filea fileb` - makes fileb’s mode the same as filea’s
+ `chmod u+s /bin/executable` - set `setuid` (`4000`) bit in `/bin/executable`
+ `chmod g+s /data/dir` - set `setgid` (`2000`) bit in `/data/dir`
+ `chmod +t /tmp` - set `sticky bit`
+ `find mydir -type f -exec chmod a-x {} ';'` - change permissions only to _files_ rather than both _files_ and _dirs_.
+ `find / -perm /4000` - find all binaries with `setuid` permissions
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
+ `du --max-depth 1 -hx /` - View root directory usage considering only the `/` filesytem and not the other directories within it with dedicated filesystems.
+ `lsblk` who lists all _block devices_ depends on `/sys/dev/block`

**Filesystems and System Tree Layout**
+ `man hier` - information about tipical linux directories `var`, `etc`, `usr`, etc.
+ `mount -o nosuid /dev/sda1 /home/alonso` - mount `/dev/sda1` filesystem without allowing using `setuid` executables in it.
+ `mount` - list mounted filesystems
+ `mount -t iso9660 -o loop image.iso /mnt/iso_image` - mount ISO file as a device
+ `man proc` - shows `/proc` filesystem information
+ `umount -l /home/alonso` - umount filesystem lazily, when opened files are closed
+ `fuser -vc /home/alonso` - list information of processes who have opened files in the filesystem mountpoint


**Managing Processes**
+ `ipcs` -  default it shows information about all three resources: shared memory segments, message queues, and semaphore arrays.

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
+ `systemd-analyze blame` - get info about systemd startup time order by unit time
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

**Logging**
+ `lastlog` - reports the most recent login of all users or of a given user out of `/var/log/lastlog`
+ `systemd journal` has volatile logs by default, they do not survive between restarts
+ `journalctl --since=yesterday --until=now --unit=docker` - show all logs of `docker` from yesterday up to now
+ `journalctl -n 100 /usr/sbin/sshd` - list the last 100 journal entries of the `sshd` daemon
+ `journalctl --grep=ERROR --unit=httpd` - show journal entries with ERROR pattern of the `httpd` daemon
+ `journalctl -b 0 -u ssh` - list `ssh` entries from the boot `0` (more recent one)
+ `journalctl --dmesg` - show kernel journal entries
+ `journalctl --unit sshd --output json` -  output the journal entries in JSON format
+ `journalctl --unit docker --until "1 hour ago" --output json-pretty` - show the logs of `docker` daemon from the last hour in a pretty-json format
+ `journalctl --unit docker --priority 3` -  show PRIORITY (like syslog) log entries only
+ `journalctl /usr/bin/dockerd` - show log entries generated by a binary executable
+ `journalctl _PID=13145` - show log entries of process with `PID 13145`
+ `/etc/logrotate.conf` - configuration for `logrotate` daemon


**Biografía**
+ Rethinking PID 1 - http://0pointer.de/blog/projects/systemd.html
+ Systemd webpage - https://www.freedesktop.org/wiki/Software/systemd/
+ ¿What is the purpose of the `initramfs` file?  - https://wiki.gentoo.org/wiki/Initramfs/Guide
