#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0; // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_waitx(void)
{
  uint64 addr, addr1, addr2;
  uint wtime, rtime;
  argaddr(0, &addr);
  argaddr(1, &addr1); // user virtual memory
  argaddr(2, &addr2);
  int ret = waitx(addr, &wtime, &rtime);
  struct proc *p = myproc();
  if (copyout(p->pagetable, addr1, (char *)&wtime, sizeof(int)) < 0)
    return -1;
  if (copyout(p->pagetable, addr2, (char *)&rtime, sizeof(int)) < 0)
    return -1;
  return ret;
}
uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if (growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n)
  {
    if (killed(myproc()))
    {
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}
uint64
sys_trace()
{
  int m;
  int chk = argint(0, &m);
  if (chk < 0)
  {
    return -1;
  }
  else
  {
    myproc()->mask = m;
    return 0;
  }
}

uint64
sys_sigalarm(void)
{
  uint64 adr;
  int ticks;

  argint(0, &ticks);
  argaddr(1, &adr);
  if (ticks < 0 || adr < 0)
  {
    return -1;
  }
  else
  {
    myproc()->ticks = ticks;
    myproc()->handler = adr;

    return 0;
  }
}
uint64
sys_sigreturn(void)
{
  struct proc *p = myproc();
  p->a_on = 0;
  p->cticks = 0;
  memmove(p->trapframe, p->atf, PGSIZE);
  int ret = p->trapframe->a0;
  kfree(p->atf);
  p->atf = 0;
  return ret;
}
uint64
sys_set_priority()
{
  int pid, priority;
  int c1 = argint(0, &priority);
  int c2 = argint(1, &pid);
  int ret;
  if (c1 < 0 || c2 < 0)
  {
    ret = -1;
  }
  else
  {
    ret = set_priority(priority, pid);
  }
  return ret;
}
int sys_settickets(void)
{
  int num_tickets;
  argint(0, &num_tickets);
  int ret;
  if (num_tickets <= 0)
  {
    ret = -1;
  }
  else
  {
    set_tickets(num_tickets);
    ret = 0;
  }
  return ret;
}