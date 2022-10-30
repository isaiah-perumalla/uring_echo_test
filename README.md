## simple IO_URING Example of tcp and udp echo server
### Requires linux-kernel version >= 6.0
1. usage of ring provided, registered buffers,  to avoid copy from kernel to usespace
2. FIXED fd for udp socket


## Build Compile
1. get liburing submodule `git submodule --init update `
2. build liburing 
```
./configure --prefix=../local-build
make
make install
```

