#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include "mmap.h"
#include <stddef.h>
#include "elf.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;


int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;

  // Initialize the mappings array to "empty" or "null" state
  // TODO: COME BACK HERE FOR FORKING! VAR WHEN NEW PROCESS IS STARTED, RESET WHEN MMAP 
  for (int i = 0; i < 32; i++) {
      p -> mappings[i].addr = NULL;
      p -> mappings[i].length = 0;
      p -> mappings[i].prot = 0;
      p -> mappings[i].flags = 0;
      p -> mappings[i].fd = 0;
  }

  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  int childProcInd = 0;
  for (int i = 0; i < 32; i++) {
    int flags = curproc -> mappings[i].flags;

    if (flags & MAP_SHARED) {
      pte_t* parent_pte = walkpgdir(curproc -> pgdir, curproc->mappings[i].addr, 0);
      int parent_pa = PTE_ADDR((int)*parent_pte);
      char * parent_va = (char*)P2V(parent_pa);

    if(mappages(np -> pgdir, (void*)curproc -> mappings[i].addr, PGSIZE, (int)V2P(parent_va), PTE_W | PTE_U) < 0) {
      cprintf("error: mappages in MAP_FIXED");
    }

    np->mappings[childProcInd].addr = (void*)curproc -> mappings[i].addr;
    np->mappings[childProcInd].fd = curproc->mappings[i].fd;
    np->mappings[childProcInd].flags = curproc->mappings[i].flags;
    np->mappings[childProcInd].length = curproc->mappings[i].length;
    np->mappings[childProcInd].prot = curproc->mappings[i].prot;

    childProcInd++;
    }

    if (flags & MAP_PRIVATE) {
      pte_t *pgdir = np -> pgdir;
      void* mem = kalloc();
      
      if (mem == 0) {
            cprintf("error: kalloc killed fork rawr xD");
      }
      if (curproc -> mappings[i].addr == 0) {
        continue;
      }

      pte_t* parent_pte = walkpgdir(curproc -> pgdir, curproc->mappings[i].addr, 0);
      int parent_pa = PTE_ADDR((int)*parent_pte);
      char * parent_va = (char*)P2V(parent_pa);

      memmove(mem, (void*)parent_va, PGSIZE);

      if(mappages(pgdir, (void*)curproc -> mappings[i].addr, PGSIZE, (int)V2P(mem), PTE_W | PTE_U) < 0) {
        cprintf("error: mappages in MAP_FIXED");
      }

      np->mappings[childProcInd].addr = (void*)curproc -> mappings[i].addr;
      np->mappings[childProcInd].fd = curproc->mappings[i].fd;
      np->mappings[childProcInd].flags = curproc->mappings[i].flags;
      np->mappings[childProcInd].length = curproc->mappings[i].length;
      np->mappings[childProcInd].prot = curproc->mappings[i].prot;

      childProcInd++;
    }
  }

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

void *mmap(void *addrInit, int length, int prot, int flags, int fd, int offset) {

  void* addr = addrInit;

  // modes of op
  if(flags & MAP_ANONYMOUS) { // anonymous mem allocation -- similar to malloc
    // MAP_ANONYMOUS is 1 -- ignore fd & offset

    if(flags & MAP_FIXED) { // if set, mapping must be placed exactly at addr

      if ((int)addr < MMAPBASE || (int)addr > KERNBASE) {
        cprintf("error: address out of bounds you silly goose! (MMAP)\n");
        return (void*)-1;
      }

      pte_t *pgdir = myproc() -> pgdir;
      // check if free spot -- dont allocate yet !!
      void * pte = walkpgdir(pgdir, addr, 0); // returns pointer to PTE if exists, creates PTE if not
      // check if this is vaid
      if (pte == NULL) {
        //idk
      }
      
      // make sure pte is not taken !!! get pte without allocating it first to make sure it's not taken duh
      void * mem = kalloc();
      memset(mem, 0, length); // length or pagesize?
      // installs mappings into a PT for a range of virtual addresses to a corresponding range of physical addresses
      // here is where you actually allocate it !!!
      if(mappages(pgdir, (void*)PGROUNDDOWN((int)addr), PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
        cprintf("error: mappages in MAP_FIXED");
      }
 
    } else { // not MAP_FIXED -- ignore addr!

      pte_t *pgdir = myproc() -> pgdir;
      void* mem;
      int i=0;
      // loop through all spaces to look for an open spot
      for(i=MMAPBASE; i<KERNBASE; i+=PGSIZE) {  // i represents addr here
        if(walkpgdir(pgdir, (void*)i, 0) == 0) { // free to map to
          mem = kalloc(); // VA ref to PA
          memset(mem, 0, length); // length or pagesize?
          // installs mappings into a PT for a range of virtual addresses to a corresponding range of physical addresses
          // here is where you actually allocate it !!!
          if(mappages(pgdir, (void*)i, PGSIZE, (int)V2P(mem), PTE_W | PTE_U) < 0) {
            cprintf("error: mappages in MAP_FIXED");
          }
          addr = (void*)i;
          break;
        }
     }

    } // cont map_anon

      // make the struct, then iterate through
      struct mapping mappings;
      mappings.addr = addr;
      mappings.length = length;
      mappings.flags = flags;
      mappings.prot = prot;
      mappings.fd = fd;

      int isMapped = 0;
      for (int i = 0; i < 32; i++) {
        if (myproc() -> mappings[i].addr == NULL) {
          myproc() -> mappings[i] = mappings;
          isMapped = 1;
          break;
        }
      }

        if(!isMapped) {
          cprintf("error: address %p could not be mapped\n", addr);
          return (void*)-1;
        }

      return addr;
     
  } else { // file-backend -- create a memory representation of a file
    // hint from piazza for working w fd: you want a file pointer. Read sysfile.c on how to get this.
    struct proc *curproc = myproc();

    if(flags & MAP_FIXED) { // place at exact address!!

      if ((int)addr < MMAPBASE || (int)addr > KERNBASE) {
        cprintf("error: address out of bounds you silly goose! (MMAP fd)\n");
        return (void*)-1;
      }

      pte_t *pgdir = myproc() -> pgdir;
      // check if free spot -- dont allocate yet !!
      void * pte = walkpgdir(pgdir, addr, 0); // returns pointer to PTE if exists, creates PTE if not
      // check if this is valid
      if (pte == NULL) {
        cprintf("error: pte should not be null\n");
        return (void*)-1;
      }
      
      // make sure pte is not taken !!! get pte without allocating it first to make sure it's not taken duh
      void * mem = kalloc();

      
      memset(mem, 0, length); // length or pagesize?
      // installs mappings into a PT for a range of virtual addresses to a corresponding range of physical addresses
      // here is where you actually allocate it !!!
      if(mappages(pgdir, (void*)PGROUNDDOWN((int)addr), PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
        cprintf("error: mappages in MAP_FIXED");
      }

    } else { // addr does not matter!
      pte_t *pgdir = myproc() -> pgdir;
      void* mem;
      int i=0;
      // loop through all spaces to look for an open spot
      for(i=MMAPBASE; i<KERNBASE; i+=PGSIZE) {  // i represents addr here
        if(walkpgdir(pgdir, (void*)i, 0) == 0) { // free to map to
          mem = kalloc(); // VA ref to PA
          memset(mem, 0, length); // length or pagesize?
          // installs mappings into a PT for a range of virtual addresses to a corresponding range of physical addresses
          // here is where you actually allocate it !!!
          if(mappages(pgdir, (void*)i, PGSIZE, (int)V2P(mem), PTE_W | PTE_U) < 0) {
            cprintf("error: mappages in MAP_FIXED");
          }
          addr = (void*)i;
          break;
        }
     }
    }
    
      // open & read file
      struct file *file = curproc -> ofile[fd];
      // read file into VA (besides that it is essentially same as map_anon)
      int read = fileread(file, addr, length); // copies file contents into addr
      if(read < 0) {
        cprintf("error: file failed to read :(\n");
        return (void*)-1;
      }

      // shared matters for the write
      struct mapping mappings;
      mappings.addr = addr;
      mappings.length = length;
      mappings.flags = flags;
      mappings.prot = prot;
      mappings.fd = fd;

      int isMapped = 0;
      for (int i = 0; i < 32; i++) {
        if (myproc() -> mappings[i].addr == NULL) {
          myproc() -> mappings[i] = mappings;
          isMapped = 1;
          break;
        }
      }

      if(!isMapped) {
        cprintf("error: address %p could not be mapped\n", addr);
        return (void*)-1;
      } 

      return addr;

  }

  // shouldn't get here!!
  return (void*)-1;

}

// removes length bytes starting at addr from the process virtual space
int munmap(void *addr, int length) {  // TODO: do we know if actually working? the answer is no!

  // error handling
  if ((int)addr < MMAPBASE || (int)addr > KERNBASE) {
    cprintf("error: address out of bounds you silly goose!(MUNMAP1)\n");
    return -1;
  } else if ((int)addr + length > KERNBASE) {
    cprintf("error: length + address out of bounds you silly goose! (MUNMAP2)\n");
    return -1;
  }

  // TODO: 
  // make sure addr page aligned
  // need to get fd from process's mapping (have to find correct mapping -- FIX FORLOOP)
  // 


  pte_t* currPTE;
  void* alignedAddr = (void*)PGROUNDDOWN((int)addr);

  // goal is to get fd by going through mappings of currProc -- make sure it actually exists, otherwise fail!
  for(int i=0; i<32; i++) {// int i=(int)addr; i<(int)addr + length; i++) { // make sure bitch (me) is actually there
    // check if addresses match, grab fd if they do -- once found, free that address and writeback to the file (4 or 5 lines of code!)
    if(myproc()->mappings[i].addr == alignedAddr) {
      if((*(currPTE = walkpgdir(myproc() -> pgdir, myproc()->mappings[i].addr, 0)) & PTE_P)) { // something allocated here 
      // convert to physical address, pteaddr -> make sure not 0
        // get fd
        if(!(myproc()->mappings[i].flags & MAP_ANONYMOUS) && (myproc()->mappings[i].flags & MAP_SHARED)) { // BE MINDFUL OF THE WAY YOU'RE BITMASKING
          struct file *file1 = myproc() -> ofile[myproc()->mappings[i].fd];
          file1->off = 0; // off is where it starts writing chars
          filewrite(file1, alignedAddr, length);
        }
        
        uint pa = PTE_ADDR(*currPTE);
        char* va = P2V(pa);
        kfree((char*)va); // only need to free start of the page
        *currPTE = 0;
        myproc()->mappings[i].addr = NULL;
        break;
        // TODO: consider full suite of reinitializing
      } 
    }
  }
  return 0; // successful!
}