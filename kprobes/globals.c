#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h> /* min */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h> /* copy_from_user, copy_to_user */
#include <linux/slab.h>
#include <linux/kprobes.h>
#include "kernels.h"

// #define MAX_SYMBOL_LEN	64
// static char symbol[MAX_SYMBOL_LEN] = "_do_fork";
// module_param_string(symbol, symbol, sizeof(symbol), 0644);

// // /* For each probe you need to allocate a kprobe structure */
// static struct kprobe kp = {
// 	.symbol_name	= symbol,
// };

// char *buffer_mm = NULL;

static const char *filename = "lkmc_mmap";

enum { BUFFER_SIZE = 4 };


struct mmap_info *info = NULL;
int Length = 128;
//info = (struct mmap_info*)kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
//pr_info("virt_to_phys = 0x%llx\n", (unsigned long long)virt_to_phys((void *)info));
//info->data = (char *)get_zeroed_page(GFP_KERNEL);


// static int handler_pre(struct kprobe *p, struct pt_regs *regs)
// {
//     return 0;
// }

// static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
// { 
// if(buffer_mm == NULL){
//     printk("buffer is null");
//     return;
// }	
// int len = sprintf(buffer_mm, "<%s> post_handler: p->addr = 0x%px, flags = 0x%lx\n",
// 		p->symbol_name, p->addr, regs->flags);
//     printk(KERN_INFO "result is %s",buffer_mm);
//     }

// /*
//  * fault_handler: this is called if an exception is generated for any
//  * instruction within the pre- or post-handler, or when Kprobes
//  * single-steps the probed instruction.
//  */
// static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
// {
// 	pr_info("fault_handler: p->addr = 0x%px, trap #%dn", p->addr, trapnr);
// 	/* Return 0 because we don't handle the fault. */
// 	return 0;
// }

/* After unmap. */
static void vm_close(struct vm_area_struct *vma)
{
    pr_info("vm_close\n");
}

/* First page access. */
static int vm_fault(struct vm_fault *vmf)
{
    struct page *page;
    //struct mmap_info *info;

    pr_info("vm_fault\n");
    info = (struct mmap_info *)vmf->vma->vm_private_data;
    if (info->data) {
        page = virt_to_page(info->data);
        get_page(page);
        vmf->page = page;
    }
    return 0;
}

/* After mmap. TODO vs mmap, when can this happen at a different time than mmap? */
static void vm_open(struct vm_area_struct *vma)
{
    pr_info("vm_open\n");
}

static struct vm_operations_struct vm_ops =
{
    .close = vm_close,
    .fault = vm_fault,
    .open = vm_open,
};

static int mmap(struct file *filp, struct vm_area_struct *vma)
{
    pr_info("mmap\n");
    vma->vm_ops = &vm_ops;
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
   
    vma->vm_private_data = filp->private_data;
    
    //vma->vm_private_data = buffer_mm;
    vm_open(vma);
    return 0;
}

static int open(struct inode *inode, struct file *filp)
{
    //struct mmap_info *info;

    pr_info("open\n");
    // info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
    // pr_info("virt_to_phys = 0x%llx\n", (unsigned long long)virt_to_phys((void *)info));
    // info->data = (char *)get_zeroed_page(GFP_KERNEL);
    // //buffer_mm = info->data;
    // memcpy(info->data, "hhhg", BUFFER_SIZE);
    filp->private_data = info;
    return 0;
}

// static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
// {
//     //struct mmap_info *info;
//     ssize_t ret;

//     pr_info("read\n");
//     if ((size_t)BUFFER_SIZE <= *off) {
//         ret = 0;
//     } else {
//         info = filp->private_data;
//         ret = min(len, (size_t)BUFFER_SIZE - (size_t)*off);
//         if (copy_to_user(buf, info->data + *off, ret)) {
//             ret = -EFAULT;
//         } else {
//             *off += ret;
//         }
//     }
//     return ret;
// }

static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    //struct mmap_info *info;
    len = min(len, info->in - info->out); /*可读数据*/
    // do {
    //     len = min(len, info->in - info->out); /*可读数据*/
    // } while (len <= 0);
    /* first get the data from info->out until the end of the buffer*/
    //int l = min(len, info->size - (info->out & (info->size -1)));
    //copy_to_user(buf, info->data + (info->out & (info->size -1)), l);
 
 /* then get the rest (if any) from the beginning of the buffer*/
    //copy_to_user(buf + l, info->data, len - l);
    // ssize_t ret;
    //printk("user can find: %s",buf);

    // pr_info("read\n");
    // if ((size_t)BUFFER_SIZE <= *off) {
    //     ret = 0;
    // } else {
    //     info = filp->private_data;
    //     ret = min(len, (size_t)BUFFER_SIZE - (size_t)*off);
    //     if (copy_to_user(buf, info->data + *off, ret)) {
    //         ret = -EFAULT;
    //     } else {
    //         *off += ret;
    //     }
    // }
    info->out += len;
    //printk("out is %d",info->out);
    return len;
}

static ssize_t write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    //struct mmap_info *info;

    pr_info("write\n");
    info = filp->private_data;
    if (copy_from_user(info->data, buf, min(len, (size_t)BUFFER_SIZE))) {
        return -EFAULT;
    } else {
        return len;
    }
}

static int release(struct inode *inode, struct file *filp)
{
    //struct mmap_info *info;

    pr_info("release\n");
    // info = filp->private_data;
    // free_page((unsigned long)info->data);
    // kfree(info);
    filp->private_data = NULL;
    return 0;
}

static const struct file_operations fops = {
    .mmap = mmap,
    .open = open,
    .release = release,
    .read = read,
    .write = write,
};

static int myinit(void)
{
    proc_create(filename, 0, NULL, &fops);
   
    info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
    //pr_info("virt_to_phys = 0x%llx\n", (unsigned long long)virt_to_phys((void *)info));
    info->data = (char *)get_zeroed_page(GFP_KERNEL);

    memcpy(info->data, "hhhg", BUFFER_SIZE);
    info->size = 4096;
    info->in = info->out = 0;
    printk("struct defined");

    return 0;
}

static void myexit(void)
{
    remove_proc_entry(filename, NULL);
    //unregister_kprobe(&kp);
}

EXPORT_SYMBOL_GPL(info);
EXPORT_SYMBOL_GPL(Length);
module_init(myinit)
module_exit(myexit)
MODULE_LICENSE("GPL");
