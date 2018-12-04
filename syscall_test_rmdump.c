
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <errno.h>
#include <linux/dynamic_dump_stack.h>

#define INSDUMP_SYSCALL 359
#define RMDUMP_SYSCALL 360

int main(int argc, char *argv[]) {

	char symbol_name[40];
	struct dumpmode_t input;
	int ret = 0, dumpstackid;
	int dumpstackmode;

	printf("Please enter dump stack mode:-");
    	scanf("%d", &dumpstackmode);

	input.mode = dumpstackmode;
	snprintf(symbol_name, sizeof(char)*40, "%s", "sys_open");
	
	// syscall to add the dump stack probe
	ret = syscall(INSDUMP_SYSCALL,symbol_name, &input);
	if(ret < 0){
		printf("ERROR While Adding the Dump Stack");
		return -1;
	}
	dumpstackid = ret;
	printf("DUMPSTACKID %d\n", dumpstackid);

	// removing the dump stack added by same process
	ret = syscall(RMDUMP_SYSCALL,dumpstackid);
	if(ret < 0){
		printf("ERROR While removind the Dump Stack");
		return -1;
	}
	printf("DUMPSTACKID %d is removed\n", dumpstackid);
	return 0;
}
