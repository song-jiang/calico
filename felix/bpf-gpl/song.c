// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>

#include "bpf.h"
#include "types.h"
#include "log.h"
#include "skb.h"
#include "routes.h"
#include "reasons.h"
#include "icmp.h"
#include "fib.h"
#include "parsing.h"
#include "failsafe.h"
#include "jump.h"
#include "metadata.h"

/*
#define map_symbol(name, ver) name##ver

#define MAP_LOOKUP_FN(name, ver) \
static CALI_BPF_INLINE void * name##_lookup_elem(const void* key)	\
{									\
	return bpf_map_lookup_elem(&map_symbol(name, ver), key);	\
}

#define CALI_MAP(name, ver,  map_type, key_type, val_type, size, flags, pin)		\
struct bpf_map_def_extended __attribute__((section("maps"))) map_symbol(name, ver) = {	\
	.type = map_type,								\
	.key_size = sizeof(key_type),							\
	.value_size = sizeof(val_type),							\
	.map_flags = flags,								\
	.max_entries = size,								\
	CALI_MAP_TC_EXT_PIN(pin)							\
};											\
	MAP_LOOKUP_FN(name, ver)

CALI_MAP(cali_v4_state, 3,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		__u32, struct cali_tc_state,
		1, 0, MAP_PIN_GLOBAL)

static CALI_BPF_INLINE struct cali_tc_state *state_get(void)
{
	__u32 key = 0;
	return cali_v4_state_lookup_elem(&key);
}
*/

/* calico_xdp is the main function used in all of the xdp programs */
static CALI_BPF_INLINE int calico_xdp(struct xdp_md *xdp)
{
	/* Initialise the context, which is stored on the stack, and the state, which
	 * we use to pass data from one program to the next via tail calls. */
	struct cali_tc_ctx ctx = {
		.state = state_get(),
		.xdp = xdp,
		.fwd = {
			.res = XDP_PASS, // TODO: Adjust based on the design
			.reason = CALI_REASON_UNKNOWN,
		},
	};

	if (!ctx.state) {
		return XDP_PASS; // TODO: Adjust base on the design
	}

	return XDP_DROP;
}

#ifndef CALI_ENTRYPOINT_NAME_XDP
#define CALI_ENTRYPOINT_NAME_XDP calico_entrypoint_xdp
#endif

// Entrypoint with definable name.  It's useful to redefine the name for each entrypoint
// because the name is exposed by bpftool et al.
__attribute__((section(XSTR(CALI_ENTRYPOINT_NAME_XDP))))
int xdp_calico_entry(struct xdp_md *xdp)
{
	return calico_xdp(xdp);
}

char ____license[] __attribute__((section("license"), used)) = "GPL";
