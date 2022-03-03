/* https://github.com/cirosantilli/linux-kernel-module-cheat#kprobes
 *
 * Adapted from: https://github.com/torvalds/linux/blob/v4.17/samples/kprobes/kprobe_example.c
 */

/*
 * NOTE: This example is works on x86 and powerpc.
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when _do_fork() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/kprobes.txt
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever _do_fork() is invoked to create a new process.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include "kernels.h"
#include <linux/device.h>


#define MAX_SYMBOL_LEN	64
#define MODULES_NUM 40
#define KPS_NUM 42

struct file* fp = NULL;
loff_t wpos = 0;

struct kprobe kps[KPS_NUM] = {
	{.symbol_name    = "sys_fork",},
	{.symbol_name    = "sys_read",},
	{.symbol_name    = "sys_write",},
	{.symbol_name    = "sys_mmap",},
	{.symbol_name    = "sys_open",},
	{.symbol_name    = "sys_mprotect",},
	{.symbol_name    = "sys_newstat",},
	{.symbol_name    = "sys_newfstat",},
	{.symbol_name    = "sys_newlstat",},
	{.symbol_name    = "sys_poll",},
	{.symbol_name    = "sys_access",},
	{.symbol_name    = "sys_pipe",},
	{.symbol_name    = "sys_select",},
	{.symbol_name    = "sys_shmget",},
	{.symbol_name    = "sys_shmat",},
	{.symbol_name    = "sys_shmctl",},
	{.symbol_name    = "sys_lseek",},
	{.symbol_name    = "sys_rt_sigaction",},
	{.symbol_name    = "sys_rt_sigreturn",},
	{.symbol_name    = "sys_dup",},
	{.symbol_name    = "sys_dup2",},
	{.symbol_name    = "sys_getpid",},
	{.symbol_name    = "sys_lseek",},
	{.symbol_name    = "sys_socket",},
	{.symbol_name    = "sys_connect",},
	{.symbol_name    = "sys_accept",},
	{.symbol_name    = "sys_sendto",},
	{.symbol_name    = "sys_recvfrom",},
	{.symbol_name    = "sys_sendmsg",},
	{.symbol_name    = "sys_recvmsg",},
	{.symbol_name    = "sys_bind",},
	{.symbol_name    = "sys_listen",},
	{.symbol_name    = "sys_execve",},
	{.symbol_name    = "sys_exit",},
	{.symbol_name    = "sys_kill",},
	{.symbol_name    = "sys_symlink",},
	{.symbol_name    = "sys_rename",},
	{.symbol_name    = "sys_mkdir",},
	{.symbol_name    = "sys_rmdir",},
	{.symbol_name    = "sys_creat",},
	//40

	{.symbol_name    = "sys_nanosleep",},
	{.symbol_name    = "sys_brk",}
};

static int count = 0;
int ret;

#define REGISTER_PROBE(x) do{ \
	pr_info("ready to register_kprobe %d.\n", x);\
	kps[x].pre_handler = handler_pre;\
	kps[x].post_handler = handler_post;\
	kps[x].fault_handler = handler_fault;\
	ret = register_kprobe(&(kps[x]));\
	if (ret < 0) {\
		pr_err("register_kprobe failed, returned %d\n", ret);\
		return ret;\
	}\
	pr_info("register_kprobe %d success.\n", x);\
} while (0)

#define UNREGISTER_PROBE(x) unregister_kprobe(&(kps[x]))

#define AMODE (O_RDWR|O_CREAT|O_APPEND)
const char * logpath = "/home/xjf/afl-sys/logs/temp.txt";
static void refresh_params(void);
static long test_module_ioctl(struct file *, unsigned int, unsigned long);

static void refresh_params(void){
	count = 0;

	if(!IS_ERR(fp)){
		// close and reopen the file to clean its content.
        int r = filp_close(fp, NULL);
        // printk("close ret:%d\n", r);
		fp = filp_open(logpath, O_WRONLY|O_CREAT|O_TRUNC, 0666);
		if(IS_ERR(fp)){
			printk("cannot open the write file.\n");
			fp = NULL;
			return;
		}
    }else{
		printk("Error closing file.\n");
		return;
	}

}

// to communicate with user programs
static int      majorNumber;
static struct   class*  test_module_class = NULL;
static struct   device* test_module_device = NULL;
#define DEVICE_NAME "test"      //define device name
#define CLASS_NAME  "test_module"

static const struct file_operations test_module_fo = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = test_module_ioctl,
};

static long test_module_ioctl(struct file *file,        /* ditto */
                 unsigned int cmd,      /* number and param for ioctl */
                 unsigned long param)
{
        switch(cmd){
        case 0:
        {
			refresh_params();
			printk(KERN_INFO "[Module:] Inner function (ioctl 0) finished.\n");
			break;
        }
        default:
			printk(KERN_INFO "[Module:] Unknown ioctl cmd!\n");
			return -EINVAL;
        }
        return 0;
}


static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{  
	if(count >= 200){
		return;
	}
	// filtering
	if(strcmp(current->comm, "toTest")){
		return;
	}

    char buf[150];
    // struct file *file = (struct file *)regs->di;//因为x86的参数传递规则是di，si，dx，cx，r8，r9，所以di就是vfs_write的第一个参数。arm默认是r0，r1，r2，r3，相应的取r0
    // size_t size = 0;
    // size = regs->dx + 1;
	// if (!strcmp(current->comm,"users") || !strcmp(current->comm,"gnome-terminal-") ) return;
	// int a =sprintf(buf, "event = %d, process = %s, pid = %ld, syscall = vfs_write, file = %s, size = %ld\n" , i, current->comm, current->pid, file->f_path.dentry->d_name.name, size);
	//int ret = sprintf(buf, "%d, process:%s, event:%s, pid=%ld.\n", count, current->comm, p->symbol_name, current->pid);
	int bufsize = sprintf(buf, "%s\n", p->symbol_name+4);
	if(bufsize<0){
		printk("sprintf fail(Emm?)\n");
		return;
	}

	//new record
	ssize_t size = kernel_write(fp, buf, bufsize, &wpos);
	if(size <= 0){
		printk("kernel_write fail, ret:%d, buf:%s\n", bufsize, buf);
	}

	//if the buffer is full, we stop putting data into it
	// int len = min(Length, info->size - info->in + info->out);
	// int l = min(len, info->size - (info->in & (info->size -1)));
    // memcpy(info->data + (info->in & (info->size -1)), buf, l);
	// memcpy(info->data, buf + l, len - l);
	// info->in += len;

	count = count + 1;
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%px, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

static int __init kprobe_init(void)
{
	// 在加载本模块时，首先向操作系统注册一个chrdev，也即字节设备，三个参数分别为：主设备号（填写0即为等待系统分配），设备名称以及file_operation的结构体。返回值为系统分配的主设备号。
    majorNumber = register_chrdev(0, DEVICE_NAME, &test_module_fo);
	if(majorNumber < 0){
			printk(KERN_INFO "[TestModule:] Failed to register a major number. \n");
			return majorNumber;
	}
	printk(KERN_INFO "[TestModule:] Successful to register a major number %d. \n", majorNumber);
	// register device class
	test_module_class = class_create(THIS_MODULE, CLASS_NAME);
	if(IS_ERR(test_module_class)){
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_INFO "[TestModule:] Class device register failed!\n");
		return PTR_ERR(test_module_class);
	}
	printk(KERN_INFO "[TestModule:] Class device register success!\n");
	// register as a device
	test_module_device = device_create(test_module_class, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(test_module_device)){               // Clean up if there is an error
		class_destroy(test_module_class);           // Repeated code but the alternative is goto statements
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create the device\n");
		return PTR_ERR(test_module_device);
	}
	printk(KERN_INFO "[TestModule:] Test module register successful. \n");



	// register file
	fp = filp_open(logpath, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if(IS_ERR(fp)){
		printk("cannot open the write file.\n");
		// fp = NULL;
		return 0;
	}
	int i;
	for(i=0;i<MODULES_NUM;++i){
		REGISTER_PROBE(i);
	}
	
	return 0;
}

static void __exit kprobe_exit(void)
{
	int i;

	for(i=0;i<MODULES_NUM;++i){
		UNREGISTER_PROBE(i);
	}

	//退出时，依次清理生成的device, class和chrdev。这样就将系统/dev下的设备文件删除，并自动注销了/proc/devices的设备。
	printk(KERN_INFO "[TestModule:] Start to clean up module.\n");
	device_destroy(test_module_class, MKDEV(majorNumber, 0));
	class_destroy(test_module_class);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	printk(KERN_INFO "[TestModule:] Clean up successful. Bye.\n");

	if(!IS_ERR(fp))
    {
        printk("closing fs file.\n");
        int r = filp_close(fp, NULL);
        printk("close ret:%d\n", r);
    }
	else{
		printk("Error closing file.\n");
		return;
	}

	// free_page((unsigned long)info->data);
	// kfree(info);
	pr_info("total events %d\n",count);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
