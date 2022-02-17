// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later


// stdbool.h has no deps so it's OK to include; stdint.h pulls in parts
// of the std lib that aren't compatible with BPF.
#include <stdbool.h>

#include "bpf_helpers.h"
#include "ebpf.h"

#include "bpf.h"
#include "types.h"
#include "log.h"
#include "skb.h"
#include "routes.h"
#include "reasons.h"
#include "parsing.h"
#include "failsafe.h"
#include "jump.h"
//#include "metadata.h"

// declare ring buffer

//ebpf_map_definition_in_file_t trace_map = {
    //.size = sizeof(ebpf_map_definition_in_file_t), .type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};
#pragma clang section data = "maps"
ebpf_map_definition_in_file_t trace_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),  //dest ip as key
    .value_size = sizeof(cali_tc_state_t),
    .max_entries = 1024};

inline void
update_trace_entry(__u8 flags, cali_tc_state_t* state)
{
    __be32 key_flags = (__be32)flags;
	__be32 key_ip = state->ip_dst;

    // if key_ip is 0, use key_flags
	if (!key_ip) {
		state->flags = flags
		bpf_map_update_elem(&trace_map, &key_flags, state, 0);
		return
	}

	// use key_ip
    bpf_map_update_elem(&trace_map, &key_ip, state, 0);
	return
}

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
		//CALI_DEBUG("State map lookup failed: PASS\n");
		return XDP_PASS; // TODO: Adjust base on the design
	}

	__builtin_memset(ctx.state, 0, sizeof(*ctx.state));

	if (CALI_LOG_LEVEL >= CALI_LOG_LEVEL_INFO) {
		ctx.state->prog_start_time = bpf_ktime_get_ns();
	}

	(void)update_trace_entry(1, ctx.state);

	// Parse packets and drop malformed and unsupported ones
	switch (parse_packet_ip(&ctx)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	(void)update_trace_entry(2, ctx.state);

	tc_state_fill_from_iphdr(&ctx);

	switch(tc_state_fill_from_nexthdr(&ctx)) {
	case PARSING_ERROR:
		goto deny;
	case PARSING_ALLOW_WITHOUT_ENFORCING_POLICY:
		goto allow;
	}

	(void)update_trace_entry(3, ctx.state);

	/*
	// Skip XDP policy, and hence fall through to TC processing, if packet hits an
	// entry in the inbound ports failsafe map.  The point here is that flows through
	// configured failsafe ports should be allowed and NOT be accidentally untracked.
	if (is_failsafe_in(ctx.state->ip_proto, ctx.state->dport, ctx.state->ip_src)) {
		//CALI_DEBUG("Inbound failsafe port: %d. Skip policy\n", ctx.state->dport);
		ctx.state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}

	// Similarly check against the outbound ports failsafe map.  The logic here is
	// that an outbound failsafe port <cidr>:<port> means to allow outbound connection
	// to IPs in <cidr> and destination <port>.  But then the return path - INBOUND,
	// and FROM <cidr>:<port> - will come through this XDP program and we need to make
	// sure that it is (a) not accidentally marked as DoNotTrack, (b) allowed through
	// to the TC program, which will then check that it matches a known outbound
	// conntrack state.
	if (is_failsafe_out(ctx.state->ip_proto, ctx.state->sport, ctx.state->ip_src)) {
		//CALI_DEBUG("Outbound failsafe port: %d. Skip policy\n", ctx.state->sport);
		ctx.state->pol_rc = CALI_POL_ALLOW;
		goto allow;
	}
	*/

	// Jump to the policy program
	//CALI_DEBUG("About to jump to policy program.\n");
	//bpf_tail_call(xdp, &cali_jump, PROG_INDEX_POLICY);
	//bpf_tail_call(xdp, &cali_jump, 7);

allow:
	(void)update_trace_entry(8, ctx.state);
	return XDP_PASS;

deny:
	(void)update_trace_entry(9, ctx.state);
	return XDP_DROP;
}

/* This program contains "default" implementations of the policy program
 * which ip will load for us when we're attaching a program to a xdp hook.
 * This allows us to control the behaviour in the window before Felix replaces
 * the policy program with its generated version.*/

/*
__attribute__((section("calico_entrypoint_xdp/0")))
int calico_xdp_norm_pol_tail(struct xdp_md *xdp)
{
	//CALI_DEBUG("Entering normal policy tail call: PASS\n");
	return XDP_PASS;
}
*/

/*
__attribute__((section("calico_entrypoint_xdp/1")))
int calico_xdp_accepted_entrypoint(struct xdp_md *xdp)
{
	//CALI_DEBUG("Entering calico_xdp_accepted_entrypoint\n");
	// Share with TC the packet is already accepted and accept it there too.
	//if (xdp2tc_set_metadata(xdp, CALI_META_ACCEPTED_BY_XDP)) {
		//CALI_DEBUG("Failed to set metadata for TC\n");
	//}
	return XDP_PASS;
}
*/

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
