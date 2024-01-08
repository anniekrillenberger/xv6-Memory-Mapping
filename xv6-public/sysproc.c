#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// like malloc, with file-backend mapping capabilities
// get a pointer to a memory region with size specified to access and use (just like me fr)
int sys_mmap(void) {

  // get parameters from user space & error handle (void *mmap(void*, int, int, int, int, int, int))
  void* addr;
  int len,      // length of mapping in bytes
      prot,     // what ops are allowed (r/w), always PROT_READ | PROT_WRITE
      flags,    // MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE, MAP_FIXED, or MAP_GROWSUP
      fd,       // file-backed mapping, file descriptor for the file to be mapped
      offset;   // will always be 0

  if(argint(1, &len) < 0 || argint(2, &prot) < 0 || argint(3, &flags) < 0 || argint(4, &fd) < 0 
    || argint(5, &offset) < 0 || argint(0, (int*) &addr) < 0)   return -1;

  return (int)mmap((void*) addr, len, prot, flags, fd, 0);
}

// removes length bytes starting at addr from the process virtual address space
int sys_munmap(void) {

  void* addr;   // starting point
  int length;   // length in bytes to remove

  if(argint(0, (int*)&addr) < 0 || argint(1, &length)) return -1;
  
  return munmap(addr, length);
}