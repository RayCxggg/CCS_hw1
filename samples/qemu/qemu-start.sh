qemu-system-aarch64 -cpu cortex-a57 -smp 4 -m 2048M -M virt -nographic \
	-kernel kernel_image \
	-append "console=ttyAMA0 root=/dev/vda init=/linuxrc rw" \
	-drive format=raw,file=busybox-1.31.1-rootfs_ext4.img 
    # -fsdev local,security_model=passthrough,id=fsdev0,path=/home/chexijia/CCS_hw1/samples/qemu \
	# -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

