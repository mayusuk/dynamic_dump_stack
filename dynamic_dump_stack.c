#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include<linux/string.h>
#include<linux/kprobes.h>
#include<linux/kallsyms.h>
#include<linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>

#include <linux/dynamic_dump_stack.h>

#define MAX_SYMBOL_LEN 40

int dumpstackid;
struct list_head dump_stack_list = LIST_HEAD_INIT(dump_stack_list);
struct dump_stack_struct *node;


// structure to store the info of all the dynamic dump stack probes
struct dump_stack_struct{

	int dumpstackid; // id of the dump stack
	char symbol_name[40];
	struct kprobe p;
	pid_t pid;   // owner pid
	pid_t threadgid;  // thread group id
	int dumpstackmode;  // mode
	struct list_head dlist;

};


// to store the temporary list of all the kprobes added by the exiting process
struct delete_node {
	struct list_head listnode;
	struct list_head* address;	
};


/*
	Method to remove the kprobes added by the process
	Gets called before existing the process
	process id is passed
*/
int remove_krpobes(pid_t pid) {

    
    struct list_head* iter = NULL;
    struct dump_stack_struct* struct_iter = NULL;

    struct delete_node *delList, *temp = NULL;
    struct list_head nodes_to_delete = LIST_HEAD_INIT(nodes_to_delete);
  
    pr_info("PROCESS %d IS EXITED. REMOVING THE KRPOBES\n", pid);
  
	// find all the kprobes added by the process
    list_for_each(iter, &dump_stack_list) {
	struct_iter = list_entry(iter, struct dump_stack_struct, dlist);
	//pr_info("PROBES - symbol %s pid %d\n", struct_iter->symbol_name, struct_iter->pid);
	if(struct_iter->pid == pid) {
		unregister_kprobe(&struct_iter->p);   // unregister the kprobes
		delList = kmalloc(sizeof(struct delete_node), GFP_KERNEL);
		memset(delList, 0, sizeof(struct delete_node));
		delList->address = iter;
		list_add(&delList->listnode, &nodes_to_delete);
	}
    }
     

	// delete entries from the global list 
   list_for_each(iter, &nodes_to_delete) {
	temp = list_entry(iter, struct delete_node, listnode);
	list_del(temp->address); 
   }

    pr_info("REMOVED THE KRPOBES\n");
    
    return 1;
}

int Pre_Handler(struct kprobe *probe, struct pt_regs *regs){
	
    struct dump_stack_struct *current_struct;
    struct task_struct* task = current;
    pid_t tgid;
    pid_t pid;
    tgid = task->tgid;
    pid = task->pid;
	
    current_struct = container_of(probe, struct dump_stack_struct, p);

    // If mode >1
    // do dump stack for all the processs
    if(current_struct->dumpstackmode > 1){   
   	 dump_stack();
    }

    // If mode = 0
    // do dump stack for the parent process only
    else if(current_struct->dumpstackmode == 0 && pid == current_struct->pid){   
   	 dump_stack();
    }
    
    // If mode = 1
    // do dump stack for all the processs who has parent pid as owner process id
    // and shares the same address space as parent process
    else if(current_struct->dumpstackmode == 1 && (pid == current_struct->pid || tgid == current_struct->threadgid)){            
   	 dump_stack();
    }
   	
    return 0;
}


SYSCALL_DEFINE1(rmdump, int, dumpid){

#ifdef CONFIG_DYNAMIC_DUMP_STACK
	
    
    struct list_head* iter = NULL;
    bool dump_stack_id_exists = false;
    struct dump_stack_struct* struct_iter = NULL;
    struct task_struct* task = current;
    pid_t pid = task->pid;
    pr_info("IN THE SYSCALL RMDUMP\n");	

    // find the kprobe with the given  dumpstack id
    list_for_each(iter, &dump_stack_list) {
	struct_iter = list_entry(iter, struct dump_stack_struct, dlist);
	if(struct_iter->dumpstackid == dumpid && struct_iter->pid == pid) {
		 // ensure that current process id is same as the owner process id
		dump_stack_id_exists = true;
		break;
	}
    }
   
    if(dump_stack_id_exists){
	printk(KERN_INFO "DUMPSTACK FOUND!! REMOVING\n");
        // unregister the krpobe
	// delete the entry from the global table
	unregister_kprobe(&struct_iter->p);
	list_del(iter);
        
    }else{
	printk(KERN_INFO "DUMPSTACK NOT FOUND\n");
	return -EINVAL;
    }
	return 1;
#else
	return 0;
#endif
    

}

SYSCALL_DEFINE2(insdump,const char __user *, symbolname, struct dumpmode_t __user *, dumpmode)
{
	  	
#ifdef CONFIG_DYNAMIC_DUMP_STACK
		
        unsigned long address;
	
	char *symbol_name;
	struct task_struct* task;
	struct dumpmode_t input_mode;
	pid_t tgid;
 	pid_t pid;
	task = current;
	tgid = task->tgid;
	pid = task->pid;
	pr_info("IN THE SYSCALL INSDUMP\n");
	symbol_name = kmalloc(sizeof(char)*MAX_SYMBOL_LEN, GFP_KERNEL);
        strncpy_from_user((char *)symbol_name,
				symbolname, MAX_SYMBOL_LEN);
    	address = kallsyms_lookup_name(symbol_name);   // find the address of the symbol
	
	if(address == 0/* && is_kernel_text(address)*/){   // validate the address
		printk(KERN_INFO "SYMBOL NOT FOUND\n");
		return -EINVAL;
	}
	
	printk(KERN_INFO "SYMOBOL FOUND! ADDING THE KRPOBE\n");
	node = (struct dump_stack_struct *)kmalloc(sizeof(struct dump_stack_struct), GFP_KERNEL);
	memset(node, 0, sizeof(struct dump_stack_struct));
	if (copy_from_user(&input_mode, dumpmode,sizeof(input_mode))){
		return -EFAULT;
	}
	printk(KERN_INFO "DUMPSTACK MODE IS - %d\n", input_mode.mode);
	node->pid = pid;
	node->threadgid = tgid;
	node->dumpstackmode = input_mode.mode;
	snprintf(node->symbol_name, sizeof(char)*MAX_SYMBOL_LEN, "%s", symbol_name);
	//node->p = (struct kprobe*)kmalloc(sizeof(struct kprobe), GFP_KERNEL);
	memset(&node->p, 0, sizeof(struct kprobe));
	node->p.pre_handler = Pre_Handler;
    	node->p.addr = (kprobe_opcode_t *)address;
	node->dumpstackid = dumpstackid++;

	// register the krpobe
	if(register_kprobe(&node->p)){
		printk(KERN_INFO "Error while setting kprobe on address %p\n", (void*)(address));\
		return -EINVAL;
	}

	// add entry to the global list
	list_add(&node->dlist, &dump_stack_list);
	printk(KERN_INFO "KPROBE INSERTED\n");
	return node->dumpstackid;
#else	
	return 0;
	
#endif
        
}
