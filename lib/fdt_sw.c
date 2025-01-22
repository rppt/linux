#include <linux/libfdt_env.h>
#include <linux/module.h>
#include "../scripts/dtc/libfdt/fdt_sw.c"

EXPORT_SYMBOL_GPL(fdt_begin_node);
EXPORT_SYMBOL_GPL(fdt_end_node);
EXPORT_SYMBOL_GPL(fdt_getprop);
EXPORT_SYMBOL_GPL(fdt_node_check_compatible);
EXPORT_SYMBOL_GPL(fdt_path_offset);
EXPORT_SYMBOL_GPL(fdt_property);
