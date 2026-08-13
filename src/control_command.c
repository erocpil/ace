#include <stdio.h>
#include <string.h>
#include "control_command.h"
#include "task_protocol.h"

/*
 * Command table.  The theme codes MUST match task_type[] in task.h:
 *   sf/sendfile  -> TASK_THEME_SENDFILE
 *   perf/performance -> TASK_THEME_PERF
 *   probe        -> TASK_THEME_PROBE
 * Keep the two tables in sync when adding task types.
 */
static const struct {
	const char *word;
	size_t len;
	uint16_t theme;
} control_commands[] = {
	{ "sf",          2,  TASK_THEME_SENDFILE },
	{ "sendfile",    8,  TASK_THEME_SENDFILE },
	{ "perf",        4,  TASK_THEME_PERF },
	{ "performance", 11, TASK_THEME_PERF },
	{ "probe",       5,  TASK_THEME_PROBE },
};

static int control_match_command(const unsigned char *s, size_t len)
{
	for (size_t i = 0; i < sizeof(control_commands) / sizeof(control_commands[0]); i++) {
		if (len == control_commands[i].len &&
		    memcmp(s, control_commands[i].word, len) == 0)
			return control_commands[i].theme;
	}
	return -1;
}

/* Parse a decimal serial token (bounded, no strtoul, no NUL assumption).
 * Rejects empty / non-digit / negative / out-of-range input. */
static int control_parse_serial(const unsigned char *s, size_t len, uint16_t *out)
{
	uint32_t v = 0;

	if (len == 0)
		return -1;

	for (size_t i = 0; i < len; i++) {
		unsigned char c = s[i];
		if (c < '0' || c > '9')
			return -1;   /* '-', '+', or non-digit */
		v = v * 10 + (uint32_t)(c - '0');
		if (v > TASK_MAX_DATA_STREAMS)
			return -1;   /* overflow / out of range */
	}
	*out = (uint16_t)v;
	return 0;
}

enum control_parse_status control_command_parse(
	const unsigned char *input, size_t input_len,
	size_t *consumed, struct sk_buff **output)
{
	size_t line_end = 0;
	size_t consumed_len = 0;
	int terminated = 0;

	/* consumed and output are required out-parameters; NULL is a caller bug,
	 * not a parse condition, so fail closed rather than crash. */
	if (!consumed || !output)
		return CONTROL_PARSE_INVALID;

	*consumed = 0;
	*output = NULL;

	if (!input || input_len == 0)
		return CONTROL_PARSE_INCOMPLETE;

	/* Locate the line terminator. */
	while (line_end < input_len) {
		if (input[line_end] == '\n' || input[line_end] == '\r') {
			terminated = 1;
			break;
		}
		line_end++;
	}

	if (!terminated) {
		if (input_len >= CONTROL_MAX_LINE) {
			*consumed = input_len;   /* drop the oversized buffer */
			return CONTROL_PARSE_INVALID;
		}
		return CONTROL_PARSE_INCOMPLETE;
	}

	/* Consume the terminator, folding CRLF into one. */
	consumed_len = line_end + 1;
	if (input[line_end] == '\r' && line_end + 1 < input_len &&
	    input[line_end + 1] == '\n')
		consumed_len = line_end + 2;

	if (line_end >= CONTROL_MAX_LINE) {
		*consumed = consumed_len;
		return CONTROL_PARSE_INVALID;
	}

	/* Empty line: skip it, nothing to parse. */
	if (line_end == 0) {
		*consumed = consumed_len;
		return CONTROL_PARSE_OK;
	}

	/* --- command word --- */
	size_t cmd_end = 0;
	while (cmd_end < line_end && input[cmd_end] != ' ')
		cmd_end++;
	if (cmd_end == 0) {
		*consumed = consumed_len;
		return CONTROL_PARSE_INVALID;
	}

	int theme = control_match_command(input, cmd_end);
	if (theme < 0) {
		*consumed = consumed_len;
		return CONTROL_PARSE_INVALID;
	}

	/* --- serial --- */
	size_t serial_start = cmd_end + 1;
	if (serial_start >= line_end) {
		*consumed = consumed_len;
		return CONTROL_PARSE_INVALID;
	}
	size_t serial_end = serial_start;
	while (serial_end < line_end && input[serial_end] != ' ')
		serial_end++;

	uint16_t serial;
	if (control_parse_serial(input + serial_start,
				 serial_end - serial_start, &serial) != 0) {
		*consumed = consumed_len;
		return CONTROL_PARSE_INVALID;
	}

	/* --- payload (optional) --- */
	size_t payload_start = serial_end + 1;
	if (payload_start > line_end)
		payload_start = line_end;
	size_t payload_len = line_end - payload_start;

	/* --- build the native head + payload sk_buff --- */
	size_t total = sizeof(struct upstream_skb_head) + payload_len + 1;
	struct sk_buff *skb = skb_malloc((ssize_t)total);
	if (!skb) {
		*consumed = consumed_len;
		return CONTROL_PARSE_INVALID;
	}
	skb_reserve(skb, sizeof(struct upstream_skb_head));
	skb_put(skb, payload_len + 1);

	struct upstream_skb_head *head = (struct upstream_skb_head*)skb->head;
	head->length = (uint32_t)(payload_len + 1);
	head->theme = (uint16_t)theme;
	head->serial = serial;
	memcpy(skb->data, input + payload_start, payload_len);
	skb->data[payload_len] = '\0';
	skb_push(skb, sizeof(struct upstream_skb_head));

	*output = skb;
	*consumed = consumed_len;
	return CONTROL_PARSE_OK;
}

int control_response_encode(
	const struct sk_buff *input, unsigned char *output,
	size_t output_size, size_t *written)
{
	if (!input || !input->head || !written)
		return -1;

	const struct upstream_skb_head *head =
		(const struct upstream_skb_head*)input->head;

	char tmp[64];
	int n = snprintf(tmp, sizeof(tmp), "\n%u %u %u\n",
			 (unsigned)head->length, (unsigned)head->theme,
			 (unsigned)head->serial);
	if (n < 0)
		return -1;

	size_t need = (size_t)n + 1;   /* include trailing NUL, as upstream_write_char does */

	if (!output) {
		*written = need;         /* dry run */
		return 0;
	}
	if (output_size < need) {
		*written = need;
		return -1;
	}
	memcpy(output, tmp, need);
	*written = need;
	return 0;
}
