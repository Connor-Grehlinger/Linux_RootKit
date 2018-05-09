# Linux_RootKit

A "malicious" program which installs a kernel module that does the following actions on the target machine:
-> copies the contents of /etc/passwd (used for user authentication) to /tmp/passwd
-> adds a fake authentication line to the /etc/passwd file for a backdoor 
-> the program (sneaky_process.c) is what loads the kernel module (sneaky_mod.c)
-> the kernel module performs the following subservise activity:
  -> hides the existence of the sneaky_process executable from all "ls" and "find" commands
  -> hides the existence of the sneaky_process executable process ID 
     from "ls /proc" and "ps -a -u <current_user_id>" commands 
  -> hides the modifications to the /etc/passwd file by hooking the open 
     system call and opening /tmp/passwd instead ("cat /etc/passwd" will look normal)
  -> hides the existence of the sneaky_module from the lsmod command 
  
The program goes into an infinite loop while the kernel module is installed so the above behavior can
be tested. Entering the character 'q' will break the infinite loop and unload the kernel module.

Note: To my knowledge this will only work with Ubuntu 16.04, as that was the OS this was developed on
and targeted for. 

As with all rootkits, the malicious "sneaky_process" executeable must be run with admin privileges 
to load the kernel module. 
  
