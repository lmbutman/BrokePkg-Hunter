// antitest.c -- minimal safe kernel module used to test visibility
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_NAME "antitest"

static struct proc_dir_entry *proc_entry;

static ssize_t antitest_read(struct file *filp, char __user *buf, size_t len, loff_t *offset) {
    const char *msg = "antitest: ok\n";
    size_t msglen = strlen(msg);
    if (*offset >= msglen) return 0;
    if (len > msglen - *offset) len = msglen - *offset;
    if (copy_to_user(buf, msg + *offset, len)) return -EFAULT;
    *offset += len;
    return len;
}

static const struct proc_ops antitest_fops = {
    .proc_read = antitest_read,
};

static int __init antitest_init(void) {
    printk(KERN_INFO "antitest: loading\n");
    proc_entry = proc_create(PROC_NAME, 0444, NULL, &antitest_fops);
    if (!proc_entry) {
        printk(KERN_ERR "antitest: proc create failed\n");
        return -ENOMEM;
    }
    return 0;
}

static void __exit antitest_exit(void) {
    printk(KERN_INFO "antitest: unloading\n");
    if (proc_entry) proc_remove(proc_entry);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antitest PoC");
MODULE_DESCRIPTION("A harmless module to test module visibility");
module_init(antitest_init);
module_exit(antitest_exit);
