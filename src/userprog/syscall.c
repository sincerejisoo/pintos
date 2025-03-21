#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#include "userprog/process.h"

#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);
void create_spte_and_pin(size_t size, void * buffer, void* esp);
void find_spte_and_unpin(size_t remained_buffer_size, void* buffer_temp);
struct lock file_rw;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_rw);
}

void get_argument(int *esp, int *args, int arg_count){
  for(int i = 0; i < arg_count; i++){
    if(!is_user_vaddr(esp + i + 1) || (esp + i + 1) < 0x8048000 || (esp + i + 1) == 0){
    sys_exit(-1);
  }
    args[i] = *(esp + i + 1);
  }
}

static void
syscall_handler (struct intr_frame *f) 
{
  if(!is_user_vaddr(f->esp) || f->esp < 0x8048000 || f->esp == 0){
    sys_exit(-1);
  }
  int args[3];
  

  switch(*(int *)f->esp){
    case SYS_HALT:
      shutdown_power_off();
      break;
      
    case SYS_EXIT:
      get_argument(f->esp, args, 1);
      sys_exit(args[0]);
      break;

    case SYS_EXEC:
      get_argument(f->esp, args, 1);
      f->eax = sys_exec(args[0], f->esp);
      break;

    case SYS_WAIT:
      get_argument(f->esp, args, 1);
      f->eax = sys_wait(args[0]);
      break;

    case SYS_CREATE:
      get_argument(f->esp, args, 2);
      f->eax = sys_create((const char *)args[0], (unsigned) args[1]);
      break;

    case SYS_REMOVE:
      get_argument(f->esp, args, 1);
      f->eax = sys_remove((const char *)args[0]);
      break;

    case SYS_OPEN:
      get_argument(f->esp, args, 1);
      f->eax = sys_open((const char *)args[0]);
      break;

    case SYS_FILESIZE:
      get_argument(f->esp, args, 1);
      f->eax = sys_filesize((int)args[0]);
      break;

    case SYS_READ:
      get_argument(f->esp, args, 3);
      f->eax = sys_read((int)args[0], (void *)args[1], (unsigned) args[2], f->esp);
      break;

    case SYS_WRITE:
      get_argument(f->esp, args, 3);
      f->eax = sys_write((int)args[0], (void *)args[1], (unsigned) args[2], f->esp);
      break;

    case SYS_SEEK:
      get_argument(f->esp, args, 2);
      sys_seek(args[0], args[1]);
      break;

    case SYS_TELL:
      get_argument(f->esp, args, 1);
      f->eax = sys_tell(args[0]);
      break;

    case SYS_CLOSE:
      get_argument(f->esp, args, 1);
      sys_close(args[0]);
      break;

    case SYS_MMAP:
      get_argument(f->esp, args, 2);
      f->eax = sys_mmap(args[0], args[1]);
      break;

    case SYS_MUNMAP:
      get_argument(f->esp, args, 1);
      sys_munmap(args[0]);
      break;
  }
}


void sys_exit(int status){
  struct thread *this = thread_current();
  this->pcb->exit_code = status;
  if(!this->pcb->is_loaded){
    sema_up(&(this->pcb->sema_load));
  }
  printf ("%s: exit(%d)\n", this->name, status);
  thread_exit();
}

pid_t sys_exec(const char *file, void *esp){
  char *it = file;
  while (true) {
    if (it == NULL || !is_user_vaddr(it) || it < 0x8048000){
      sys_exit(-1);
    }
    if (*it == '\0') break;
    it++;
  }
  //create_spte_and_pin(strlen(file) + 1, (void*) file, esp);

  pid_t pid = process_execute(file);
  
  if(pid == -1){
    return -1;
  }

  //find_spte_and_unpin(strlen(file) + 1, (void *)file);

  struct pcb *child_pcb = get_child(pid)->pcb;
  if (!child_pcb->is_loaded) return -1;
  return pid;
}

int sys_wait(pid_t pid){
  return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size){
  if (file == NULL || !is_user_vaddr(file) || file < 0x8048000){
    sys_exit(-1);
  }
  lock_acquire(&file_rw);
  bool result = filesys_create(file, initial_size);
  lock_release(&file_rw);
  return result;
}

bool sys_remove(const char *file){
  if (file == NULL || !is_user_vaddr(file) || file < 0x8048000){
    sys_exit(-1);
  }
  lock_acquire(&file_rw);
  bool result = filesys_remove(file);
  lock_release(&file_rw);
  return result;
}

int sys_open(const char *file){

  if (file == NULL || !is_user_vaddr(file) || file < 0x8048000){

    sys_exit(-1);
  }
  lock_acquire(&file_rw);
  struct file *_file = filesys_open(file);
  lock_release(&file_rw);
  if (_file == NULL){

    return -1;
  }
  struct thread *this = thread_current();
  this->pcb->fd_table[this->pcb->fd_count] = _file;
  this->pcb->fd_count++;
  

  return (this->pcb->fd_count) - 1;
  
}

int sys_filesize(int fd){
  struct thread *this = thread_current();
  struct file *file = this->pcb->fd_table[fd];
  if(file == NULL){
    return 0;
  }
  return file_length(file);
}

int sys_read(int fd, void *buffer, unsigned size, void *esp){
  if (buffer == NULL || !is_user_vaddr(buffer) || buffer < 0x8048000){
    sys_exit(-1);
  }
  for (int i = 0; i < size; i++){
    if (!is_user_vaddr(buffer + i) || (buffer + i) < 0x8048000){
      sys_exit(-1);
    }
  }
  create_spte_and_pin(size, buffer, esp);

  int result = 0;
  int fd_count = thread_current()->pcb->fd_count;
  
  if (fd >= fd_count || fd < 0) {
    result = -1;
  }
  else if(fd == 0){
    lock_acquire(&file_rw);
    for (int i = 0; i < size; i++){
      ((char *)buffer)[i] = input_getc();
      if (((char *)buffer)[i] == '\0') break;
      result = i;
    }
    lock_release(&file_rw);
  }
  else {
    struct file *file = thread_current()->pcb->fd_table[fd];
    if (file == NULL){
      
      result = -1;
    }
    else {
      lock_acquire(&file_rw);
      result = file_read(file, buffer, size);
      lock_release(&file_rw);
    }
  }

  find_spte_and_unpin(size, buffer);
  return result;
}

int sys_write(int fd, const void *buffer, unsigned size, void *esp){
  if (buffer == NULL || !is_user_vaddr(buffer) || buffer < 0x8048000){
    sys_exit(-1);
  }
  for (int i = 0; i < size; i++){
    if (!is_user_vaddr(buffer + i) || (buffer + i) < 0x8048000){
      sys_exit(-1);
    }
  }

  create_spte_and_pin(size, buffer, esp);

  int result = 0;
  int fd_count = thread_current()->pcb->fd_count;
  if (fd >= fd_count || fd < 1) {
    result = -1;
  }
  else if(fd == 1){
    lock_acquire(&file_rw);
    putbuf(buffer, size);
    lock_release(&file_rw);
    result = size;
  }
  else {

    struct file *file = thread_current()->pcb->fd_table[fd];
    if (file == NULL) {

      result = -1;
    }
    else {
      lock_acquire(&file_rw);
      result = file_write(file, buffer, size);
      lock_release(&file_rw);
    }
  }

  find_spte_and_unpin(size, buffer);

  return result;
}

void sys_seek(int fd, unsigned position){
  struct file *file = thread_current()->pcb->fd_table[fd];
  int fd_count = thread_current()->pcb->fd_count;
  if (file != NULL && fd < fd_count && fd >= 0) {
    lock_acquire(&file_rw);
    file_seek(file, position);
    lock_release(&file_rw);
  }
}
unsigned sys_tell(int fd){
  struct file *file = thread_current()->pcb->fd_table[fd];
  int fd_count = thread_current()->pcb->fd_count;
  if (file == NULL || fd >= fd_count || fd < 0) return -1;
  return file_tell(file);
}
void sys_close(int fd){
  struct thread *this = thread_current();
  int fd_count = this->pcb->fd_count;
  if (fd >= fd_count || fd < 2) {
    return;
  }
  struct file *file = this->pcb->fd_table[fd];
  if (file == NULL) {
    return;
  }
  lock_acquire(&file_rw);
  file_close(file);
  lock_release(&file_rw);
  this->pcb->fd_table[fd] = NULL;
  for(int i = fd; i < fd_count - 1; i++){
    this->pcb->fd_table[i] = this->pcb->fd_table[i+1];
  }
  this->pcb->fd_count--;
  this->pcb->fd_table[fd_count] = NULL;
  
}

mapid_t sys_mmap (int fd, void *addr) {
  if(is_kernel_vaddr(addr)) sys_exit(-1);

  if(!addr || (int)addr % PGSIZE != 0) return -1;

  struct mmap_file *mfe = (struct mmap_file *)malloc(sizeof(struct mmap_file));
  if (mfe == NULL) {
    return -1;
  }   

  lock_acquire(&file_rw);
  struct file* file = file_reopen(thread_current()->pcb->fd_table[fd]);
  lock_release(&file_rw);
  int length = file_length(file);
  if (length == 0) {
    
    free(mfe);
    return -1;
  }
  
	list_init(&mfe->spte_list);
  mfe->file = file;
  off_t ofs = 0;
  
	while(length > 0) {
    if(spte_find(addr) != NULL) {
    free(mfe);
    return -1;
    }
    
    size_t read_bytes = length > PGSIZE ? PGSIZE : length;
    size_t zero_bytes = PGSIZE - read_bytes;

    struct page_entry* spte = spte_create(SPTE_FILE, addr, true, false, file, ofs, read_bytes, zero_bytes);
    if (!spte) {
      free(mfe);
      return -1;
    }
    list_push_back(&mfe->spte_list, &spte->mmap_elem);
    spte_insert(&thread_current()->SPT, spte);
    
    addr += PGSIZE;
    ofs += PGSIZE;
    length -= PGSIZE;
  }

  mfe->mapping_id = thread_current()->mmap_next_mapid++;
  list_push_back(&thread_current()->mmap_list, &mfe->elem);
  return mfe->mapping_id;
}

void sys_munmap(mapid_t mapping) {
	struct mmap_file *mfe = NULL;
  struct list_elem *it = list_begin(&thread_current()->mmap_list);
  while (it != list_end(&thread_current()->mmap_list)) {
    mfe = list_entry(it, struct mmap_file, elem);
    if (mfe->mapping_id == mapping) break;
    it = list_next(it);
  }
  if(mfe == NULL) return;

  for(it = list_begin(&mfe->spte_list); it != list_end(&mfe->spte_list);) {
    struct page_entry *spte = list_entry(it, struct page_entry, mmap_elem);
    if (spte->is_loaded) {
      if(pagedir_is_dirty(thread_current()->pagedir, spte->vaddr)){
        lock_acquire(&file_rw);
        file_write_at(spte->file, spte->vaddr, spte->read_bytes, spte->offset);
        lock_release(&file_rw);
      }
      
      free_frame(pagedir_get_page(thread_current()->pagedir, spte->vaddr));
    }
    it = list_remove(it);
    spte_delete(&thread_current()->SPT, spte);
  }
  list_remove(&mfe->elem);
  free(mfe);	
}

void create_spte_and_pin(size_t remained_buffer_size, void * buffer_temp, void * esp){
  while(remained_buffer_size > 0) {
    struct page_entry *spte = spte_find(pg_round_down(buffer_temp));
    if(spte != NULL) {
      if(!spte->is_loaded) {
        if (!fault_handler(spte)) {

          sys_exit(-1);
        }
      }
    }
    else {
      uint32_t lowest_stack_addr = PHYS_BASE - 0x800000;
      if ((buffer_temp >= (esp-32)) && (buffer_temp >= lowest_stack_addr)) {
        if (!stack_grow(buffer_temp)) {

          sys_exit(-1);
        }
      }
      else {

        sys_exit(-1);
      }
    }

    size_t read_bt = remained_buffer_size > PGSIZE - pg_ofs(buffer_temp) ? PGSIZE - pg_ofs(buffer_temp) : remained_buffer_size;
    struct frame *pin = find_frame_for_vaddr(pg_round_down(buffer_temp));
    pin_user_frame(pin->physical_page);

    remained_buffer_size -= read_bt;
    buffer_temp += read_bt;
  }
}

void find_spte_and_unpin(size_t remained_buffer_size, void* buffer_temp){
  while(remained_buffer_size > 0) {

    size_t read_bt = remained_buffer_size > PGSIZE - pg_ofs(buffer_temp) ? PGSIZE - pg_ofs(buffer_temp) : remained_buffer_size;
    struct frame *unpin = find_frame_for_vaddr(pg_round_down(buffer_temp));
    unpin_user_frame(unpin->physical_page);

    remained_buffer_size -= read_bt;
    buffer_temp += read_bt;
  }
}