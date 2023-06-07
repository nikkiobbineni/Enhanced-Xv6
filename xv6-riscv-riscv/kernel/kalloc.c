// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

struct run {
  struct run *next;
};

struct {
  struct spinlock lock;
  struct run *freelist;
} kmem;
struct {
  struct spinlock lock;
  int cnt[PGROUNDUP(PHYSTOP)>>12];
} node;

void pageinit()
{
  initlock(&node.lock, "node");
  acquire(&node.lock);
  int i;
  int c = PGROUNDUP(PHYSTOP)>>12;
  for(i=0;i<c;)
  {
    node.cnt[i++]=0;
  }
  release(&node.lock);
}

void decpage(void*pa)
{
  acquire(&node.lock);
  uint64 k;
  k = (uint64)pa >> 12;
  int c = node.cnt[k];
  if(c<=0)
  {
    panic("decpage");
  }
  node.cnt[k]--;
  release(&node.lock);
}

void ipr(void*pa)
{
  acquire(&node.lock);
  uint64 k;
  k = (uint64)pa >> 12;
  int c = node.cnt[k];
  if(c<0)
  {
    panic("ipr");
  }
  node.cnt[k]++;
 release(&node.lock);
}

int getpage(void*pa)
{
  acquire(&node.lock);
  uint64 k;
  k = (uint64)pa >> 12;
  int res; 
  res = node.cnt[k];
  if(node.cnt[k]<0)
  {
    panic("getpage");
  }
  release(&node.lock);
  return res;
}

void
kinit()
{
  pageinit();
  initlock(&kmem.lock, "kmem");
  freerange(end, (void*)PHYSTOP);
}

void
freerange(void *pa_start, void *pa_end)
{
  char *p;
  p = (char*)PGROUNDUP((uint64)pa_start);
  for(; p + PGSIZE <= (char*)pa_end; p += PGSIZE){
    ipr(p);
    kfree(p);
  }
}

// Free the page of physical memory pointed at by pa,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(void *pa)
{
  struct run *r;
  acquire(&node.lock);
  if(node.cnt[(uint64)pa>>12]<=0){
    panic("decpage");
  }
  node.cnt[(uint64)pa>>12]-=1;
  if(node.cnt[(uint64)pa>>12]>0){
    release(&node.lock);
    return;
  }
  release(&node.lock);
  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  release(&kmem.lock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r)
    kmem.freelist = r->next;
  release(&kmem.lock);

  if(r){
    memset((char*)r, 5, PGSIZE); // fill with junk
    ipr((void*)r);
  }
   return (void*)r;
}
