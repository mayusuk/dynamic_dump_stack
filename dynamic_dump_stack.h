


extern struct list_head dump_stack_list;


// function to remove the kprobes after process is completed
extern int remove_krpobes(pid_t pid);

// data strcuture to pass argument to system call
struct dumpmode_t {
	unsigned int mode;
};
