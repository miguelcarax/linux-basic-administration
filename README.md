# LFCS Cheatsheet

## Chapter 16 - Linux Filesystem and the VFS
+ **VFS** - El VFS esconde las peculiaridades de cada sistema de ficheros y unifica el manejo a través de un API común 

View all supported filesystems by the VFS. 

_The ones with nodev are special filesystems which do not reside on storage._
```
$ cat /proc/filesystems
nodev   sysfs
nodev   rootfs
nodev   ramfs
nodev   bdev
nodev   proc
...
        ext3
        ext2
        ext4
        squashfs
        vfat
        fuseblk
...
nodev   binfmt_misc
nodev   overlay
nodev   aufs
nodev   vboxsf

```
+ **rootfs** - During kernel load, provides an empty root directory
+**ramdisks** vs **tmpfs**:
    + It is not necessary to format before using. 
    + It can use both RAM and Swap.
    + It consumes memory in an efficient manner. It can resize itself.

```
$ sudo mkir /mnt/tmpfs
# Half of the RAM on default
$ sudo mount -t tmpfs -o size=1G none /mnt/tmpfs
$ df -h /mnt/tmpfs
```
+ Any user can create, read and write files in `/dev/shm` (tmpfs), so it is a good place to create temporary files in memory
<hr>

## Chapter 17 - Disk Partitioning
+ **fdisk** - manipulate disk partition table
+ **blkid** - shows information about partitions
+ **lsblk** - information about block devices in a tree form view
+ UUID, which describes the filesystem on the partition, not the partition itself. It changes if the filesystem is reformatted.
+ Device nodes for SCSI and SATA disks follow a simple xxy[z] naming convention, where xx is the device type (usually sd), y is the letter for the drive number (a, b, c, etc.), and z is the partition number:
+ In `ls`. The first character in the first column, (i.e.`crw-rw-rw-`) tells an informed user the type of the file, in this case a character device. For ordinary files, the first character is `-`, for directories it is `d` and for block devices `b`; see the ls man page for further information.
+ Easy backup Partition Table
```
# MBR
$ sudo dd if=/dev/sda of=mbrbackup bs=512 count=1
# GPT
$ sgdisk --backup=/tmp/sda_backup /dev/sda
```
+ **fdisk** or **gparted** - Manage partitions
+ System partitions - `/proc/partitions`
+ Traditional names for storage devices such as /dev/sda are not reliable for identification, as changing the port in which the disk is connected to, or attaching the disk to another server can result in a different name. Linux allows the use of labels and **UUIDs** for naming storage devices
+ You can use `uuidgen` to generate a _time_ or _random_ base UUID.
+ Each partition is treated as a separate disk with its own file system. Partition information is stored in a partition table. One partition table per block storage device.
+ Utilizar un fichero como un _block storage device_.
```
$ dd if=/dev/zero of=imagefile bs=1M count=1024
$ mkfs.ext4 imagefile
$ mkdir mntpoint
$ sudo mount -o loop imagefile mntpoint
# Enjoy!
```
<hr>

## Chapter 18 - Attributes, Creating, Checking, Mounting
+ _In computing, a file system or filesystem controls how data is stored and retrieved_
+ `lsattr` and `chattr` to modify extended attributes of files.
+ Format any filesystem - `mkfs [-t fstype] [options] [device-file]`
+ It's better to mount with the partition UUID - `sudo mount UUID=26d58ee2-9d20-4dc7-b6ab-aa87c3cfb69a /home`
+ `mount` -  list of currently mounted filesystems
+ Check errors on any filesystem - `fsck [-t fstype] [options] [device-file]`. `fsck` on the root filesystem, which is hard to do on a running system. You should run `fsck` on umounted filesystems.
+ You can use `fuser` to find out which users are using the filesystem
+ You can also use `lsof` ("list open files") to try and see which files are being used and blocking unmounting.
+ The system may try to mount the NFS filesystem before the network is up. The `netdev` and `noauto` options can be used. For more information, check man nfs, examine the mount options.