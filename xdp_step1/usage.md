# usage 

1. copy `xdp_pass_kern.c` and `xdp_pass_user.c` into kernel source code dir `samples/bpf`

2. edit Makefile in `samples/bpf` to build `xdp_pass_kern.c` and `xdp_pass_user.c` 

details: 
    - hostprogs-y += xdp_pass
    - xdp_pass-objs := bpf_load.o xdp_pass_user.o
    - always += xdp_pass_kern.o

3. execute `make M=samples/bpf` under kernel source code root dir

4. run `./samples/bpf/xdp_pass --dev eth0` to load xdp pass program into `eth0`(you can choose the nic)