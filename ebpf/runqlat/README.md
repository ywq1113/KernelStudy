# Build
```bash
make
```

# How to use

```bash
# 全局（单位：微秒，1s 打印一次；Ctrl-C 结束）
sudo ./runqlat

# 用毫秒看长尾，过滤掉 <50us 的噪声
sudo ./runqlat -u ms -m 50000

# 只看某个进程（TGID）
sudo ./runqlat -p 1234

# 只看某个线程（TID）
sudo ./runqlat -t 5678

# 固定运行 30 秒，每 2 秒出一次图
sudo ./runqlat -i 2 -d 30
```
