bzImage：目前主流的 kernel 镜像格式，即 big zImage（即 bz 不是指 bzip2），适用于较大的（大于 512 KB） Kernel。这个镜像会被加载到内存的高地址，高于 1MB。bzImage 是用 gzip 压缩的，文件的开头部分有 gzip 解压缩的代码，所以我们不能用 gunzip 来解压缩。

vmlinux：linux-5.4-98/路径下。静态链接的 Linux kernel，以可执行文件的形式存在，尚未经过压缩。该文件往往是在生成 vmlinuz 的过程中产生的。该文件适合于调试。但是该文件不是 bootable 的。

rootfs.img：busybox打包生成的文件系统。

boot.sh：qemu启动脚本。

