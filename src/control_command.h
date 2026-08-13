#ifndef __CONTROL_COMMAND_H__
#define __CONTROL_COMMAND_H__

#include <stddef.h>
#include "sk_buff.h"

/*
 * control_command — text control-command parsing and response encoding for the
 * local Unix-socket control plane.
 *
 * The wire-format codec is deliberately NOT touched here: commands are parsed
 * into the native internal head (struct upstream_skb_head) plus a payload, the
 * same layout the local upstream queue already produces.  The SEND/RECV wire
 * asymmetry is a separate concern handled at the task layer.
 */

/* Upper bound on a single command line, including its payload.  The payload is
 * a filesystem path, so PATH_MAX (4096) is a safe ceiling. */
#define CONTROL_MAX_LINE 4096U

enum control_parse_status {
	CONTROL_PARSE_OK = 0,
	CONTROL_PARSE_INCOMPLETE,   /* need more bytes (no terminator yet) */
	CONTROL_PARSE_INVALID,      /* malformed command; skip or close */
};

/*
 * control_command_parse - parse one command line from a byte buffer.
 *
 * @input      raw bytes (NOT assumed NUL-terminated); NULL means empty input
 * @input_len  number of valid bytes in @input
 * @consumed   out: bytes consumed from @input (line + terminator); 0 when
 *             CONTROL_PARSE_INCOMPLETE.  REQUIRED (non-NULL).
 * @output     out: on CONTROL_PARSE_OK, a freshly allocated sk_buff holding a
 *             native struct upstream_skb_head followed by the NUL-terminated
 *             payload; caller owns it (skb_free).  NULL on INCOMPLETE/INVALID.
 *             REQUIRED (non-NULL).
 *
 * Grammar:  <command> SP <serial> [SP <payload>] (CR? LF)
 *   command  one of the known control commands (see table below)
 *   serial   decimal integer in [0, TASK_MAX_DATA_STREAMS]
 *   payload  arbitrary bytes up to end-of-line, may be empty
 *
 * A line without a terminator yields CONTROL_PARSE_INCOMPLETE so a caller can
 * accumulate fragmented reads.  A line longer than CONTROL_MAX_LINE is
 * CONTROL_PARSE_INVALID.  On INVALID, @consumed is the bytes to skip (the bad
 * line), and no allocation is left behind.
 */
enum control_parse_status control_command_parse(
	const unsigned char *input, size_t input_len,
	size_t *consumed, struct sk_buff **output);

/*
 * control_response_encode - serialize a response line for a command head.
 *
 * @input        sk_buff whose ->head is a native struct upstream_skb_head
 * @output       caller buffer; NULL means "dry run" (compute length only)
 * @output_size  capacity of @output
 * @written      out: bytes required (including the trailing NUL); matches what
 *               upstream_write_char() writes back to the client
 *
 * Returns 0 on success, -1 if @input/@written are NULL or @output is too small.
 */
int control_response_encode(
	const struct sk_buff *input, unsigned char *output,
	size_t output_size, size_t *written);

#endif
