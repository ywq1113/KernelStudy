#include <chrono>
#include <iostream>
#include <mutex>
#include <pthread.h> // Set thread name
#include <thread>

using namespace std::chrono_literals;

std::mutex A;
std::mutex B;

void t1() {
  if (auto h = pthread_self(); true)
    pthread_setname_np(h, "thread1");
  A.lock();
  std::this_thread::sleep_for(100ms);
  B.lock();
  std::cout << "t1 acquired A->B\n";
  B.unlock();
  A.unlock();
}

void t2() {
  if (auto h = pthread_self(); true)
    pthread_setname_np(h, "thread2");
  B.lock();
  std::this_thread::sleep_for(100ms);
  A.lock();
  std::cout << "t2 acquired B->A\n";
  B.unlock();
  A.unlock();
}

int main() {
  std::this_thread::sleep_for(15s); // 等待 ebpf 程序附加
  std::thread x(t1);
  std::thread y(t2);
  x.join();
  y.join();
  return 0;
}
