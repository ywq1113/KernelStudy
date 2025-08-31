# Build

```bash
cd deadlock
# Compiler example program
clang++ -g -W -d examples/abba.cpp -o abba -lpthread
# Compiler ebpf program
make
```

# Test

```
wizyang@iZ2ze1jfcxmpxa35tu6n5nZ:~/work/KernelStudy/ebpf/deadlock$ clang++ -g -W -d examples/abba.cpp -o abba -lpthread
wizyang@iZ2ze1jfcxmpxa35tu6n5nZ:~/work/KernelStudy/ebpf/deadlock$ ./abba &
[1] 39482
wizyang@iZ2ze1jfcxmpxa35tu6n5nZ:~/work/KernelStudy/ebpf/deadlock$ sudo ./deadlock_user -p 39482
deadlock (CO-RE + ringbuf) running. libpthread=/usr/lib/x86_64-linux-gnu/libc.so.6 [filter by tgid]

[DEADLOCK?] tgid=39482 root_tid=39491 comm=thread2
 chain: T39491 --wait(0x55e700ca00a0)--> T39490 --wait(0x55e700ca00c8)--> T39491 <== CYCLE
```