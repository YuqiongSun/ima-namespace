#!/bin/bash

make -j8 
#make modules
#make modules_install
make install
cp /boot/vmlinuz-4.1.0-rc1+ /home/yus138/kernel/
#cp /boot/initrd.img-4.1.0-rc1+ /home/yus138/kernel/
