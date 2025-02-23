#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

typedef void (*handler_t)(void);

struct LangTable {
  handler_t greet;
  handler_t farewell;
};

struct LangTable *g_handler = NULL;

static void english_greet(void) { printk(KERN_INFO "hello there!\n"); }
static void spanish_greet(void) { printk(KERN_INFO "hola!\n"); }
static void french_greet(void) { printk(KERN_INFO "bonjour!\n"); }

static void english_farewell(void) { printk(KERN_INFO "goodbye!\n"); }
static void spanish_farewell(void) { printk(KERN_INFO "adios!\n"); }
static void french_farewell(void) { printk(KERN_INFO "au revoir!\n"); }

struct LangTable lang_table[] = {
    {.greet = english_greet, .farewell = english_farewell},
    {.greet = spanish_greet, .farewell = spanish_farewell},
    {.greet = french_greet, .farewell = french_farewell},
};

static int zero_open(struct inode *inode, struct file *file) {
  g_handler = &lang_table[0];
  return 0;
}

static int zero_release(struct inode *inode, struct file *file) {
  g_handler = NULL;
  return 0;
}

enum CMD { CMD_SET, CMD_GREET, CMD_FAREWELL };

static long zero_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

  if (cmd == CMD_SET) {
    switch (arg) {
    case 0:
      g_handler = &lang_table[0];
      break;
    case 1:
      g_handler = &lang_table[1];
      break;
    case 2:
      g_handler = &lang_table[2];
      break;
    default:
      return -EINVAL;
    }
  } else if (cmd == CMD_GREET) {
    g_handler->greet();
  } else if (cmd == CMD_FAREWELL) {
    g_handler->farewell();
  } else {
    return -EINVAL;
  }

  return 0;
}

struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = zero_open,
    .release = zero_release,
    .unlocked_ioctl = zero_ioctl,
};

struct miscdevice zero = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "chal",
    .fops = &fops,
};

static int zero_init(void) { return misc_register(&zero); }

static void zero_exit(void) { misc_deregister(&zero); }

module_init(zero_init);
module_exit(zero_exit)
