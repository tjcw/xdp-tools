/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include "xsk_def_xdp_prog.h"

#define DEFAULT_QUEUE_IDS 64

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC(".maps");

struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xsk_def_prog);

tatic __always_inline void display_one(int index) {
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
//	if(mapped != NULL) {
		bpf_printk("index%d mapped=%p\n", index, mapped) ;
//	}
}

static __always_inline void display_all(void) {
	display_one(0) ;
	display_one(1) ;
	display_one(2) ;
	display_one(3) ;
	display_one(4) ;
	display_one(5) ;
	display_one(6) ;
	display_one(7) ;
	display_one(8) ;
	display_one(9) ;
	display_one(10) ;
	display_one(11) ;
	display_one(12) ;
	display_one(13) ;
	display_one(14) ;
	display_one(15) ;
	display_one(16) ;
	display_one(17) ;
	display_one(18) ;
	display_one(19) ;
	display_one(20) ;
	display_one(21) ;
	display_one(22) ;
	display_one(23) ;
	display_one(24) ;
	display_one(25) ;
	display_one(16) ;
	display_one(27) ;
	display_one(28) ;
	display_one(29) ;
	display_one(30) ;
	display_one(31) ;
	display_one(32) ;
	display_one(33) ;
	display_one(34) ;
	display_one(35) ;
	display_one(36) ;
	display_one(37) ;
	display_one(38) ;
	display_one(39) ;
	display_one(40) ;
	display_one(41) ;
	display_one(42) ;
	display_one(43) ;
	display_one(44) ;
	display_one(45) ;
	display_one(46) ;
	display_one(47) ;
	display_one(48) ;
	display_one(49) ;
	display_one(50) ;
	display_one(51) ;
	display_one(52) ;
	display_one(53) ;
	display_one(54) ;
	display_one(55) ;
	display_one(56) ;
	display_one(57) ;
	display_one(58) ;
	display_one(59) ;
	display_one(60) ;
	display_one(61) ;
	display_one(62) ;
	display_one(63) ;
}

/* This is the program for post 5.3 kernels. */
SEC("xdp")
int xsk_def_prog(struct xdp_md *ctx)
{
	/* A set entry here means that the corresponding queue_id
	 * has an active AF_XDP socket bound to it.
	 */
	display_all() ;
    int index = ctx->rx_queue_index;
	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	if( k_tracing ) bpf_printk("index=%d mapped=%p\n", index, mapped) ;
//	return XDP_PASS;
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);
