qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -initrd  rootfs.img \
    -append "root=/dev/null rw console=ttyS0 oops=panic panic=1 kaslr" \
    -smp cores=2,threads=1 \
    -cpu kvm64