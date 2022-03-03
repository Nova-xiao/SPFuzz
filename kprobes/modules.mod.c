#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xaf381eb0, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xa430d826, __VMLINUX_SYMBOL_STR(device_destroy) },
	{ 0x59c003a0, __VMLINUX_SYMBOL_STR(unregister_kprobe) },
	{ 0x3b2fba82, __VMLINUX_SYMBOL_STR(register_kprobe) },
	{ 0x942cfb36, __VMLINUX_SYMBOL_STR(class_destroy) },
	{ 0xd532c445, __VMLINUX_SYMBOL_STR(device_create) },
	{ 0x6bc3fbc0, __VMLINUX_SYMBOL_STR(__unregister_chrdev) },
	{ 0x76a81688, __VMLINUX_SYMBOL_STR(__class_create) },
	{ 0xebc215d0, __VMLINUX_SYMBOL_STR(__register_chrdev) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xcc8dd2e8, __VMLINUX_SYMBOL_STR(kernel_write) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x9b65a65f, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xb77d2a19, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0x2b0ed5ed, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "FD9BCB33B451888DAE9C214");
