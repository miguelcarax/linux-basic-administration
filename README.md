# Linux Administration Basics

**BASH**
+ `/etc/environment` is the first file loaded by `bash` shell
+ `/etc/shells` - system wide availables shells
+ `/etc/profile` - system wide file loaded with logins shells
+ `/etc/bashrc` -  system wide file loaded with logins and non-logins shells
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
+ `!d` - execute the last command that started with a `d`
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
+ `uuidgen` - generate random uuid like this `58847587-38ae-485b-be63-0d5cac6c8a6b`
+ `elinks` - text based browser

**GIT**
+ `git diff --name-only --diff-filter=U` - show files with conflicts
+ `git checkout -- file` - delete changes made to `file` file
+ `git log --oneline --decorate --all --graph`
+ `git revert HEAD~1` or `git revert 676ec`
+ `git checkout 676ec` - use `git checkout branch_name` to go back to last commit

**Hadoop**
+ `hdfs dfs -ls -C hdfs:///path` - print only the name of the directories or files
+ `hdfs dfs -ls -S hdfs:///path` - list output sorted by size
+ `hdfs dfs -count -h hdfs:///path` - get numer of files, directories and size of `/path` in human-redeable
+ `HADOOP_ROOT_LOGGER=DEBUG,console hadoop distcp...` - get `DEBUG` info when runing `hdfs` command 
+ `yarn application -list`

**SQL**
+ `DESCRIBE FORMATTED table_name PARTITION (dt='20131023')` - show location of an specific partition
+ `SHOW CREATE TABLE table_name` - get the DDL of the table

**Python**
+ `pip show sparkmagic`
+ `pip install numpy`
+ `pip-check` - https://pypi.org/project/pip-check/

**VIM**
+ `:%s/\s\+$//e` - remove all trailling spaces

**Security**
+ `man limits.conf` - information about `ulimit` 
+ `ulimit` - provides control over the resources available to the shell and to processes started by it
+ `ulimits -a` - list current user shell limits
+ `/etc/pam.d/login` - PAM configuration file for `login` command
+ `man pam_X` - get information about `pam_X` PAM module
+ `man pam.d` - get information about generic PAM modules

**TLS**
+ `openssl s_client -connect myservice.es:443 -showcerts </dev/null` - print all certificates in the certificate chain presented by the SSL service
+ `openssl verify -CAfile rootca.pem intca.pem` - verify `intca.pem` against `rootca.pem`
+ `openssl verify -CAfile <(cat rootca.pem intca.pem ) server-cert.pem` - verify `server-cert.pem` against cert chain `rootca.pem` + `intca.pem`
+ `openssl s_client -connect myservice.es:443 -CAfile <(cat rootca.pem intca.pem)` - veriry `myservice.es` cert against cert chain `rootca.pem` + `intca.pem`
+ `keytool -keystore myapplication-keystore.jks -alias myapplication -genkey -keyalg RSA -keypass 123456 -storepass 123456` - generate a JKS keystore with key pairs and alias `myapplication`
+ `keytool -certreq -alias myapplication -keystore myapplication-keystore.jks -file myapplication.csr -ext san=dns:myapplication,dns:myapplication.mycorporation.com -storepass 123456 -keypass 123456` - generate a CSR out of an existing `myapplication` key pairs in a JKS
+ `keytool -importcert -alias CAroot -file CAroot.pem -keystore myapplication-keystore.jks` - import the custom CA `CAroot.pem` to the keystore to be able to import the signed certificate, signed by this CA
+ `keytool -importcert -alias myapplication -file myapplication.pem -keystore myapplication-keystore.jks -trustcacerts` - import the signed certificated to the existing key pairs, will exchange the existing public key with the signed certificate
+ `keytool -genkey -v -keyalg RSA -keystore myapplication-keystore.jks -keypass 123456 -storepass 123456 -storetype jks -alias myapplication -validity 3650 -dname "CN=myapplication.mycorporation.com,C=ES,ST=Madrid,L=Madrid,O=MyBusiness"`
+ `openssl x509 -inform der -in myapplication.cer -out myapplication.pem` - convert `x509` certificate from `DER` format to `PEM`
+ `openssl pkcs12 -in certificado.p12 -out certificado.pem -clcerts -nokeys` - extract the `x509` public certificate out of a `PKCS#12` store
+ `openssl pkcs12 -in certificado.p12 -out certificado_key.pem -nocerts -nodes` - extract the private key out of a `PKCS#12` store


**Logs**
+ `/var/log/messages` - mostly all `syslog` messages are logged here
+ `/var/log/secure` - security and authentication information are logged here
+ `/var/log/boot.log` - startup and booting information are logged here
+ `man 5 rsyslog.conf` - This file specifies rules for logging
+ `lastlog` - reports the most recent login of all users or of a given user out of `/var/log/lastlog`
+ `logger` - enter messages into the system log
+ `logrotate` - rotates, compresses, and mails system logs
+ `/etc/logrotate.conf` - configuration file of logrotate daemon
+ The `systemd` service manager invokes all service processes with stdout and stderr connected to the journal by default
+ `/etc/systemd/journald.conf.d/*.conf` - change `journald` cofiguration
+ `journald` is located as volatile information in `/run/log/journal/` at default but can be configured to be persistent
+ `journalctl --disk-usage` - get info about how much are logs taking on disk
+ `systemd journal` has volatile logs by default, they do not survive between restarts
+ `journalctl --since=yesterday --until=now --unit=docker` - show all logs of `docker` from yesterday up to now
+ `journalctl --no-pager -x` - show all logs with `no-pager` and e`x`tra explaniation
+ `journalctl -n 100 /usr/sbin/sshd` - list the last 100 journal entries of the `sshd` daemon
+ `journalctl --grep=ERROR --unit=httpd` - show journal entries with ERROR pattern of the `httpd` daemon
+ `journalctl -b 0 -u ssh` - list `ssh` entries from the boot `0` (more recent one)
+ `journalctl --dmesg` - show kernel journal entries (or `-k` like `dmesg -k`)
+ `journalctl --unit sshd --output json` -  output the journal entries in JSON format
+ `journalctl --unit docker --until "1 hour ago" --output json-pretty` - show the logs of `docker` daemon from the last hour in a pretty-json format
+ `journalctl --unit docker --priority 3` -  show PRIORITY (like syslog) log entries only
+ `journalctl /usr/bin/dockerd` - show log entries generated by a binary executable
+ `journalctl -o cat --no-pager -e --unit NetworkManager` - get last logs of `NetworkManager` service without displaying the timestamp and source information, additional with no pager
+ `journalctl _PID=13145` - show log entries of process with `PID 13145`
+ `/etc/logrotate.conf` - configuration for `logrotate` daemon
+ A HUP signal causes rsyslogd to close all open log files, which is useful for rotating (renaming and restarting) logs.
 
**Time**
+ `timedatectl set-timezone Europe/Madrid` - set system TZ
+ `timedatectl status` - get system time info
+ `hwclock` - manage hardware time in the system
+ `chronyc sources` - shows the `ntp` servers used in `chrony`
+ `ntpq -pn` - same as `chronyc sources` but for `ntp`
+ `ntpdate pool.ntp.org` - Set the current date and time in that momment. Cannot be used when `ntpd` daemon is running
+ `ntpstat` - get current information about ntp
+ ` /etc/localtime -> /usr/share/zoneinfo/Europe/Madrid`
+ `/etc/ntp.conf` - `ntpd` daemon configuration file
+ `date -Iseconds` - print current time with ISO 8601 format, ex: `2020-03-17T10:57:17+0100`

**Managing software**
+ `ldd /bin/bash` - list all libraries needed by `bash` binary
+ `ldconfig` - the directories that will be searched for shared libraries, read from `/etc/ld.so.conf`. `LD_LIBRARY_PATH` environment variable can be used too
+ `libc.so.6` - shared C library 
+ `vfat.ko.xz` - compresses linux kernel module 
+ `rpm -qf /etc/httpd` - finds out which paquet the file belongs to  
+ `rpm -ql bash` - list which files does the package has installed
+ `rpm -qpl ncat.rpm` - list which files could the package install
+ `rpm -U iperf` - upgrade `iperf` package
+ `rpm -Vva` or `rpm -vV bash` - verify whether the files from a particular package are consistent with the system's RPM database
+ `rpm -ivh gedit.rpm` - install `gedit.rpm` package. Do not manage dependencies
+ `rpm -qp --scripts gedit.rpm` - show _scripts_ included in the `gedit.rpm`
+ `rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7` - import new repository GPG key
+ `rpm -q gpg-pubkey` - list installed repositories gpg-keys
+ `rpm -qi gpg-pubkey-f4a80eb5-53a7ff4b` - get more dailed informaton about `X` gpg repository key
+ `rpm2cpio sudo.rpm | cpio -ivd` - extract the content of `sudo.rpm` into current directory 
+ `yumdownloader gedit` - download locally `gedit.rpm`
+ `yum history` - shows all the executions of `yum` command
+ `yum repolist -v` - show available repositories in `/etc/yum.repos.d/*`, extended format
+ `yum list installed` - list installed packages, same as `rpm -qa`
+ `yum list installed \*bash\*` - list installed packages which match the `\*bash\*` expression
+ `yum install nmap` - install `nmap` package
+ `yum install epel-release -y` - enable EPEL repository
+ `yum localinstall nmap.rpm` - install local `nmap.rpm` package
+ `yum list available \*ftp\*` - list all available packages that match the `\*ftp\*` expression
+ `yum remove nmap` - remove `nmap` package
+ `yum groups summary` - view the number of installed groups, available groups, available environment group
+ `yum update --security` - update only packages with security updates
+ `yum update /usr/bin/bash` - update the package that provides `/usr/bin/bash` binary
+ `yum info bash` - get more detailed information about the `bash` package
+ `yum install --downloadonly --downloaddir=/tmp bash` - download `bash` package in `/tmp` dir
+ `yum reinstall bash` - reinstall `bash` package
+ `yum deplist ntp` - list all dependencies of `ntp` package
+ `yum clean all` - remove al cached information


**Man**
+ Man pages are stored in `/usr/share/man` and compressed in gzip format. `man` is able to decompress it on the fly
+ `man man`
+ `man -k keyword` - let's you find _commands_ based on `keyword`

**Network**
+ `/etc/services` - provides information about what ports are asigned to which services assigned by the IANA
+ `/etc/nsswitch.conf` - defines in which order does the system look for information
+ `/proc/sys/net/*` - linux kernel configuration values
+ `sysctl net.ipv4.icmp_echo_ignore_broadcasts=1` - configure kernel network parameter, add to `/etc/sysctl.conf` for peristence against reboots
+ `hostnamectl set-hostname myserver.localdomain` - change the server hostname, do not need reboot to take effect
+ `ping -f goo.gl` - do a ping flood
+ `ping -I eth1 goo.gl` - do a ping to `goo.gl` through the `eth1` interface
+ `traceroute goo.gl` - print the route packets trace to network host
+ `ss -tuna` is the same as `netstat -tulpn
+ `netcat -l 4444` - listen on port `4444`
+ `namp 192.168.0.23` + do a port scan `0-65536` on the IP address `192.168.0.23`
+ `nmcli` and `nmtui` (throught `NetworkManager` service) or `vim` (manually) modify interfaces configuration files in `/etc/sysconfig/network-scripts/*` but `systemd-networkd` service is responsible to apply this configurations to network interfaces
+ `/usr/share/doc/initscripts-*/sysconfig.txt` - information about `/etc/sysconfig/network-scripts/ifcfg-X` configuration files
+ `ipcalc -bn 10.0.0.0/8` - get broadcast and mask out of `10.0.0.0/8` IP address
+ `/etc/sysconfig/network` - file where you can set up the hostname, gateway, domain name, etc
+ Lines in `/etc/sysconfig/network-scripts/route-ifname` are passed as arguments to `ip route` when the corresponding interface is configured. Could be find at the end of `man ifup`
+ `ip link show` - show current network devices (link layer)
+ `man ip-address`, `man ip-link`, `man ip-route`, `man ip-neighbour` - general info in `man ip`
+ `ip link help`, `ip addr help`, etc
+ `ip -c link` - print command ouput with colors
+ `ip link set eht0 down` - set down the `eth0` network interface, same for `up`
+ `ifup eth1` or `ifdown eth1` - bridown down/up `eth1` network, **force reload** of `/etc/sysconfig/network-scripts/ifcfg-eth1` configuration file
+ `ip neigh show` - show ARP table (layer 2)
+ `ip -d addr` - show more detailed information
+ `ip addr show up` - get information about only upped interfaces
+ `ip addr show dev eth1 ` - get information about `eth1` network interface
+ `ip address add 10.0.0.3/24 dev eth1` - assign the `10.0.0.3/24` IP to `eth1` network interface
+ `ip -stat -iec -c addr ` - show stats about network (addr) layer with color
+ `ip route show` - show routing table (layer 3), same as `netstat -rn`
+ `ip route del default` - delete default gateway in routing table
+ `ip route add 132.236.220.64/26 via 132.236.212.6 dev eth1` - add entry to routing table
+ `ip route add default via 132.236.227.1 dev eth0` - add default gateway in routing table (`0.0.0.0`)
+ `ss -tuna` - list all connections, both TCp and UDP and do not resolve PORTS to SERVICES
+ `ss -tnl` - list all listening TCP connections
+ `ss -tanp` - list all TCP connections along with the process which is establishing the connection
+ `ss -s` - network connections summary
+ `ss -tun state LISTENING` - display all TCP and UDP listening ports
+ `ss -t state STABLISHED` - display all TCP established connections
+ `ss dst 90.169.220.26` - display all connections made from `90.169.220.26`
+ `ss src :ssh` - display all SSH connections at the moment or `ss sport :22`
+ `ss -o` - show how long was the connection established
+ `ss -r` - resolve from IP to DNS name in the connections
+ `firewalld` manages `iptables` that are used by `netfilter` kernel module
+ `firewalld` will transfor his configuration into `iptables` rules
+ `firewall-cmd --list-all` - get all information about current `firewalld` configuration
+ `firewall-cmd --add-service http` - add `http` service to `firewalld` configurations, NOT permanent
+ `firewall-cmd --add-service http --permanent` - add `http` service to `firewalld` configurations
+ `firewall-cmd --info-service http` - get information about `http` service
+ `firewall-cmd --reload` - reload changed configuration, like adding a service to `/etc/firewalld/services`
+ `firewall-cmd --runtime-to-permanent` - save current runtime configuration as permanent
+ `iptables -L` - show current iptables rules
+ `iptables -L -v` - show current (verbose) iptables rules
+ `iptables -P INPUT DROP` - deny all input traffic by default
+ `iptables -L INPUT -p tcp --dport 22 -j ACCEPT` - allow incoming SSH traffic
+ `iptables -A INPUT -p icmp -j DROP` - disable ping from outside
+ `iptables-save >> /etc/sysconfig/iptables-config` - save ip tables runtime configuration to persistent configuration files
+ `iptables` packet filtering logs are manage by kernel, use `dmesg` to visualize

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
+ `/etc/skel/*` - all the content of this directory will be copied to new created users' home
+ `useradd -D -s /bin/bash` - set `bash` as default shell for all new created users, modify `/etc/default/useradd` file
+ `useradd -c "David Hilbert" -d /home/math/hilbert -g hilbert -G faculty -m -s /bin/tcsh hilbert`
+ `groupadd users` - create group `users`
+ `gpasswd --delete miguelones sudo` - remove `miguelones` user from `sudo` group
+ `groupmems --group sudo --delete miguelones` - delete `miguelones` user from `sudo` group
+ `usermod -L username` - lock `username` account, this disables login. 
+ `usermod -aG docker miguelones` - add `miguelones` user to `docker` group
+ `userdel -r miguelones` - remove `miguelones` user along with his home directory and mail spool
+ `chsh -s /bin/nologin username` -  disables `username` user to login
+ `w` - shows you who is currently loged-in
+ `who` - show who is logged on
+ `loginctl list-sessions` - list current system sessions
+ `loginctl session-status 14` - get all information about session `14`
+ `loginctl list-users` - list currently logged in users
+ `loginctl user-status user` - get information about what `user` user doing
+ `loginctl terminate-user user` - terminate all sesions of `user` user
+ `last` - show listing of last logged in users

**Managing files**
+ `file` - determine file type
+ `dd if=/dev/zero of=/tmp/file bs=1M count=100` - create a file with _zeros_ with size `1MB` * `100`
+ `cpi -ivd < archive.cpio` - extract the content of the `archive.cpio` archive into current directory
+ `tar -cf file.bzip2 --bzip file` - create a `bzip2` tarball
+ `tar -czf file.tar.gz file` - create a `gzip` tarball
+ `tar -tvf file.tar.gz` - list the content of the tarball `file.tar.gz`
+ `tar -xzvf file.tar.gz` - untar `file.tar.gz` tarball
+ `tar -cf file.tar.xz --xz file` - create a `xz` tarball
+ `tar -xf file.tar -C /tmp/dir` - untar `file.tar` in `/tmp/dir`
+ `tar -cjf tarball-content.tar.bz tarball-content.tar` - further compress a `tar` file with `bzip2` compress
+ `tar -cf tarball.tar -C my_dir/my_other_dir .` -  will only add all the content of dir `my_dir/my_other_dir` to the tarball rather than `my_dir/my_other_dir/*`
+ `tar -rf tarball.tar new-file` - add `new-file` to existing archive, the tarball cannot be compressed to add new files
+ `bzip2 file` - compress `file`  wiht `bzip2` algorithm, will create `file.bz2` file , will delete original file
+ `bzip2 -k file` - compress `file` without deleting it
+ `xz -k file` - compress `file` with `xz` algorithm without deleting original file
+ `gzip` for compress and `gunzip` for decompress
+ `find / -iname A -maxdepth 1` - search with 1 level directory deep
+ `find / -iname B -mount` - don't descend directories on other filesystems
+ `find / -iname C -empty` - search for empty files/directories
+ `find / -user root` - search for all files owned by `root` user
+ `find / -path "/etc*hosts"` - like `-name` option but search for long paths rather than filenames that not allow `/` 
+ `find ~ -type f -name 'foo*' -exec ls -l '{}' +` - the `+` indicates that all founds possibilities will be passed to the `ls` command rather than executing `ls` for each ocurrence
+ `find /etc -type f -exec grep -l miguel '{}' \; -exec cp '{}' /tmp \;` - concatenate 2 `-exec` for the same found files
+ `find /etc/ -type f -exec grep -l "127.0.0.1" "{}" "+"` - exec `grep` command in all files in ``/etc` dir
+ `find /etc/ -type f -size +1M -exec cp -t /data \{\} +` - copy (in one-shot) all files with size greater than `1M` from `/etc` ot `/data` dir 
+ `find /sbin /usr/sbin -executable \! -readable -print` - search for files which are executable but not readable.
+ `find $HOME -mtime 0` - search  for files in your home directory which have been modified in the last 24 hours, same for `atime`
+ `find . -perm 664` - will match ONLY `'644` files but NOT `775`, for example
+ `find . -perm -664` - will match `644`, `755`, `777`, extra bits are not taking in consider, same as `find . -perm -u+rw,g+rw,o+r`
+ `find . -perm /222` - will match `020`, `220`, `200`, `222`, etc. Any file writable by anybody
+ `find / -perm /4000` - will match all files with `suid` bit, like `/usr/bin/passwd`
+ `find . -perm -444 -perm /222 ! -perm /111`
+ `find / -xdev -nouser` - check for orphaned files after a user has been removed
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
+ `awk -F'/' '{print $3}'` - change awk field delimiter to `/`
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
+ `chmod +t /tmp` - set `sticky bit`, the only exception to `sticky bit` is the _owner_ of the directory
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

**Filesystems and System Tree Layout**
+ `findmnt` - tree overview of current filesystems
+ `man hier` - information about tipical linux directories `var`, `etc`, `usr`, etc.
+ `man xfs`, `man ext4` - get information about mount options (and more) about `xfs` and `ext4` filesystems
+ `xfs_admin` - administrate `xfs` filesystems
+ `xfs_admin -L oreilly /dev/sdb3` - put `books` label in `/dev/sdb3` filesystem
+ `xfs_growfs /dev/vgdata/lvdata` - resize `xfs` filesytem (on top of LVM)
+ `mount` - list mounted filesystems
+ `mount -o nosuid /dev/sda1 /home/alonso` - mount `/dev/sda1` filesystem without allowing using `setuid` executables in it.
+ `mount -o noexec,ro /home/user` - mount use home without allowing executions and permitting read onlyg 
+ `mount -a` - mount all entries defined in  `/etc/fstab`
+ `mount -t iso9660 -o loop image.iso /mnt/iso_image` - mount ISO file as a device
+ `mount -U c1899275-daad-4934-8300-d4488747d5d2 /tmp` - mount by `UUID`
+ `man proc` - shows `/proc` filesystem information
+ `umount -l /home/alonso` - umount filesystem lazily, when opened files are closed
+ `fuser -vc /home/alonso` - list information of processes who have opened files in the filesystem mountpoint
+ `partprobe -s` - informs the operating system kernel of partition table changes
+ `fdisk -l /dev/sda` - display device `/dev/sda` partitions
+ `fdisk /dev/sda` - interactive manage `/dev/sda` partition table
+ `mkfs -t ext4 /dev/xvdb1` - format as `ext4` filesystem the first partition of `/dev/xvdb` device
+ `wipefs /dev/sdb4` - shows `magic string` in partition `/dev/sdb4`
+ `findfs UUID=8ac075e3-1124-4bb6-bef7-a6811bf8b870` - findfs - find a filesystem by label or UUID
+ `lsblk -fatp` - list all block-devices (partitions too) along with devices path, filesytem type and more
+ `lsblk -fatp /dev/xvbd` - get all information about `/dev/xvbd` device along with all his partitions
+ `lsblk` who lists all _block devices_ depends on `/sys/dev/block`
+ `blkid /dev/sdb1` - print block device attributes
+ `df -hTP` - get information about all filesystem in human form
+ `df -hTP -t ext4 -t xfs` - get information about filesystem with either `xfs` format or `ext4`
+ `df -hTP -x tmpfs` - get informationa about all filesystems excluding `tmpfs` filesystems like `/proc` or `/run`
+ `pvcreate /dev/xvdb[1:2]` - create `PV` out of `/dev/xvdb1` and `/dev/xvdb2` partitions
+ `pvdisplay` - show information about system LVMs, `pvs` as less detailed
+ `vgcreate vgtest /dev/xvdb[1:2]` - create `VG` `vgtest` of of `PV` `/dev/xvbd1` and `/dev/xvdb2`, will implicit create the `PV` if needed
+ `vgextend vgtest /dev/sdb4` - add new `PV` `/dev/sdb4` to `vgtest` `VG`
+ `vgdisplay` - show information about system VGs, `vgs` as less detailed
+ `lvcreate --name lvexam --size 1G vgexam` - create `LV` `lvexam` with the size of `1GB` out of `VG` `vgexam `
+ `lvcreate -l 100%FREE -n lvbooks2 vgbooks` - create `LV` using 100% of free space of the `VG` `vgbooks`
+ `lvcreate --name lvexam --size 3.99G vgexam` - you can use `X.YY` notation with `--size` parameter
+ `lvdisplay` - show information about system LVs in table view
+ `lvremove vgexam/lvexam` - remove `LV` `lvexam` out of `VG` `vgexam`
+ `lvrename vgdata/lv-data vgdata/lvdata` - rename `lv-data` to `lvdata`
+ `lvresize --size 2GB vgexam/lvexam` - resize `LV` `lvexam`
+ `lvresize --resizefs -L -100M /dev/vgbooks/lvbooks` - resize LV and resize the FS above him
+ `lvresize -L +500M /dev/vgdata/lvdata` - same as above command but other syntax
+ `lvcreate --snapshot --size 100M --name lvexam-snap vgexam/lvexam`
+ `mkswap /dev/sdb4` - format `/dev/sdb4` as `swap` filesystem
+ `swapon /dev/sdb4` - turn on swap
+ `swap` partitions should be added to `fstab` as `/dev/sdb4 swap default 0 0 `, the `swap` without a `/`
+ `cryptsetup luksFormat /dev/sdb4` - create a encrypted partition
+ `cryptsetup luksOpen /dev/sdb4 secret`
+ `mkfs -t xfs /dev/mapper/secret` - you CANNOT format a encrypted partition if is not opened before
+ `cryptsetup close secret` - close the encrypted partition
+ `/etc/crypttab` -  describes encrypted block devices that are set up during system boot. If we add an entry in this file with our encrypted partition the system will ask us at boot time for the password of the encrypted partition
+ `mdadm --create /dev/md0 --level=1 --raid-disks=2 /dev/sdb1 /dev/sdb2` - create software RAID device `/dev/md0` out of 2 partitions
+ `mdadm --create --help`

**Monitoring System**
+ `var/log/messages` - contains global system messages, including the messages that are logged during system startup
+ `/var/log/secure` - authorization and authentication information
+ `/var/log/dmesg` - kernel ring buffer information (also included in `/var/log/messages`)
+ `/var/log/kern.log` - contains information logged by the kernel.
+ `/var/log/boot.log` - startup information (booting)
+ `uptime -p` - show how many time has been the system running (pretty format)
+ `free -h` - amount of free and used memory in the system
+ `vmstat -s` - reports information about processes, memory, paging, block IO, traps, disks and cpu activity
+ `vmstat -D` - disk statistics (summary)
+ `vmstat -d` - disk statistics
+ `vmstat 2 10` - every 2 seconds, 10 times
+ `cat /proc/meminfo` - get lenght memory information
+ `dmesg -Hw` - get kernel logs ( from `/dev/kmsg`)
+ `/proc/cmdline` - show with which options was the kernel launched
+ `ipcs` -  default it shows information about all three resources: shared memory segments, message queues, and semaphore arrays.
+ `renice 0 -u user` - set niceness of `0` to all processes owned by `user` user
+ `renice -20 9207` - set niceness of `-20` o the process with pid `9207` 
+ `ps xawf -eo pid,user,cgroup,args` - Monitor which process belong to which cgroup
+ `ps -fx` - processes owned by you
+ `ps -fU user -C command` - processed runned by `user` with `command` in execution command
+ `ps -fp 2226,1154,1146` - procssed with pid `x`
+ `ps --forest -e` - show processes in a tree view form
+ `ps -fU apache -p 4770 --forest` - get all `httpd` processes along with his father process
+ `ps -p 1223 -o pid,ppid,fgroup,ni,lstart,etime,cgroup` - custom process output
+ `ps -x -o pid=` - print all processes PID owned by you in a _quiet_ form
+ `ps -ef --sort +pid` - list all system processes sorted by ascend PID
+ `ps -f -U $(whoami) --forest --sort=+pid` - get all your user processes sorted by `PID` in a `--forest` form
+ `top` - provides  a  dynamic real-time view of a running system
  + `m` - change global memory output layout
  + `l` - change global CPU output layout
  + `I` - _Iris_ mode for CPU
  + `O` - sorting by a field
  + `z` - put colors on output
  + `c` - show absolute path of processes
  + `P` - sort by CPU
  + `M` - sort by memory
  + `e` - change memory unit for individual processes memory
  + `E` - change memory unit for global memory 
  + `R` - sort by PID
  + `V` - forest view
  + `J` - justify text
  + `U` - filter by user
  + `W` - save current display options
  + `f` - select other fields to display
  + `r` - renice a process
+ `ps` and `top` read from `/proc`
+ `/usr/bin/nice -n5 date` - launch `date` command with 5 points increased _niceness_
+ `sudo /usr/bin/renice -n -10 24247` - renice process `24247` to -10 priority
+ `/proc/<pid>/maps` -  show what libraries the process depends on
+ `/proc/<pid>/fd` - file descriptors opened by the process. Can contain symlinks to real files
+ `strace` - shows system calls trace from a process
+ `crontab -e` - edit user crontab file
+ `crontab -l` - list user crontabs
+ `man 5 crontab` - get info about `crontab` format
+ You can check if a cron job has ran in `/var/log/cron`
+ `minute hour dom month weekday command` - crontab line format
+ You can put `.sh` files in `/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.monthly`, etc.
+ `20 1 * * * find /tmp -mtime +7 -type f -exec rm -f { } ';'` - crontab, it removes all files in the `/tmp` directory that have not been modified in 7 days.
+ `systemd` defines `timers` that like `cron` execute a system process on a predefined schedule. More info in `man systemd.timer`
+ A `systemd.timer` must have a `systemd.service` which determines what to run
+ `systemd-run --on-active=30 /bin/touch /tmp/foo` - create a `systemd.timer` (and associated `systemd.service`)
+ `systemd-run --on-calendar="*-*-* 22:41:00" logger hello` - create a `X.timer` (and associated `X.service`) which runs daily
+ `systemd-run --unit="test" --on-active="60" touch /tmp/file` - run the `test.service` from `60` seconds from now
+ `man 7 systemd.time` - information about `systemd.timer` scheduler format
+ `echo date | at now +5min` - execute `date` command in 5 minutes

**GRUB**
+ `grub2-install /dev/sda ` - Install grub on disk
+ `grub2-mkconfig`
+ `/etc/default/grub`
+ `/etc/grub.d/40-custom`
+ `grubby` - grubby - command line tool used to configure bootloader 
+ `grubby --bootloader-probe` - list installed bootloader
+ `grubby --default-kernel` - list default installed kernel
+ `grubby --update-kernel=/boot/vmlinuz-3.10.0-1062.12.1.el7.x86_64 --args="init=/bin/bash"` - update kernel arguments
+ Kernel options on problems - `init=/bin/bash`, `systemd.unit=emergy.target` for minimal services, `rd.break` for getting acces to the `initramfs` just before executing `chroot`
+ `dracut` - create initial ramdisk images for preloading modules
+ `/boot` - stores data used before the kernel begins executing user-mode programs
+ `/boot/vmlinuz-4.14.72-68.55.amzn1.x86_64` - Linux kernel compressed (`cpio`) file
+ `/boot/initramfs-4.14.72-68.55.amzn1.x86_64.img` - `initramfs` file for kernel
+ `lsinitrd` -  get information about current kernel `initramfs`, use with `less`
+ `Rescue Mode` in a SO installation CD will load a Kernel and an `initramfs` from the CD

**Startup, Kernel and Processes**
+ `lsmod` - list kernel modules
+ `modinfo cryptd` - get info about `cryptd` kernel module
+ `modprobe cryptd` - load `cryptd` kernel module
+ `modprobe -r cryptd` - remove `cryptd` kernel module
+ `/lib/modules/<kernel-version>` - path where kernel modules are located
+ `sysctl -a` - list all kernel runtime parameters
+ `sysctl -a --pattern forward` - list all kernel parameters that match `forward` pattern
+ `sysctl net.ipv4.ip_forward=1` - change kernel parameter `net.ipv4.ip_forward` to `1` (enabled), changes are NOT persistent
+ `/etc/sysctl.d/*.conf` - drop-in directory for kernel sysctl parameters.
+ `/etc/sysconfig/*` - are used when starting, stopping, configuring or querying system services (Red Hat)
+ `shutdown -h +5` -  halt system in 5 minutes
+ `shutdown -r now` - restart system now
+ `man bootup` - information about startup process
+ `/etc/vconsole.conf` -  default keyboard mapping and console font.
+ `/etc/systemd/system/*.target.wants/*.service` - where different systemd targets (like runlevels) units files are located
+ `systemd-cgls` - systemd cgroups info
+ `systemd-cgtop`
+ `man systemd.special` - describe basic systemd units
+ `man systemd.service` - Service unit configuration
+ `systemctl start /path/to/foo.service` - start `foo.service` by path
+ `systemctl` - show the status of everything that systemd controls
+ `systemctl -t help` - list available unit types
+ `systemctl cat docker` - cat the `docker.service` unit file
+ `systemctl list-timers` - get information about `systemd.timers` in the system
+ `systemctl list-units dock*` - list all units which match the `dock*` expression
+ `systemctl list-units -t service --all` - list all service units, despite of the state
+ `systemctl list-units -t service` - list active service units
+ `systemctl list-units --type=target` - list all available targets in systemd
+ `systemctl list-units --type=service --state=running`- list all currently `running` services
+ `systemctl list-unit-files --type=service` - list installed units
+ `systemctl list-unit-files --state=enabled` - list enabled units
+ `systemctl list-dependencies rescue.target` - list all units involved in `rescue.target`
+ `systemctl edit docker` - modifies the `docker.service` unit in `/etc/systemd/system/docker.service` leaving unmodified `/usr/lib/systemd/system/docker.service`
+ `systemctl edit --full docker` - copy the `docker.service` totally and paste it in `/etc/systemd/system/`
+ `systemctl enable sshd.service --now` - enable and start `sshd`
+ `systemctl set-default multi-user.target` - change the default run level in the system
+ `systemctl is-active docker.service`
+ `systemctl isolate rescue.target` - change execution mode to `rescue.target`
+ `systemctl rescue` - same as above command
+ `systemctl daemon-reload docker.service` - Reloads when a new service is created or any configuration is modified.
+ `systemctl reboot` - same as `systemctl start reboot.target --irreversible`
+ `systemctl poweroff` - shutdown the system
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
+ `man 7 signal` - overview of signals
+ `kill -s SIGTERM 5776` - send `SIGTERM` signal to the process with PID `5776`
+ `killall -u USER` - kill all `USER` processes
+ `kill -15 1234` - send signal number `15` to process with pid `1234`
+ `pkill python` - kill all processes that match `python` pattern, owned by any user
+ `pkill -u pablelas` - kill all `pablelas`' processes
+ `pkill -u root python` - kill all `root` processes that match `python` pattern

**Managing Services**
+ `htpasswd` -  used to store usernames and password for basic authentication of HTTP users
+ `httpd-manual` - package for provide information about configuring an HTTPD server


**Biografía**
+ Rethinking PID 1 - http://0pointer.de/blog/projects/systemd.html
+ Systemd webpage - https://www.freedesktop.org/wiki/Software/systemd/
+ ¿What is the purpose of the `initramfs` file?  - https://wiki.gentoo.org/wiki/Initramfs/Guide
+ Yum cheatsheet - https://access.redhat.com/sites/default/files/attachments/rh_yum_cheatsheet_1214_jcs_print-1.pdf
+ Conda Cheatsheet - https://docs.conda.io/projects/conda/en/latest/_downloads/843d9e0198f2a193a3484886fa28163c/conda-cheatsheet.pdf
