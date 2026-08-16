#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "control_command.h"
#include "task_protocol.h"

static void expect_parse(const char *buf,
			 enum control_parse_status want_status,
			 size_t want_consumed,
			 uint16_t want_theme, uint16_t want_serial,
			 const char *want_payload)
{
	size_t len = strlen(buf);
	size_t consumed = 0;
	struct sk_buff *out = NULL;
	enum control_parse_status st = control_command_parse(
		(const unsigned char*)buf, len, &consumed, &out);

	assert(st == want_status);
	assert(consumed == want_consumed);

	if (want_status != CONTROL_PARSE_OK) {
		assert(out == NULL);
		return;
	}

	assert(out != NULL);
	struct upstream_skb_head *head = (struct upstream_skb_head*)out->head;
	assert(head->theme == want_theme);
	assert(head->serial == want_serial);
	assert(head->length == (uint32_t)(strlen(want_payload) + 1));
	assert(strcmp((const char*)out->head + sizeof(struct upstream_skb_head),
		      want_payload) == 0);
	skb_free(out);
}

static void test_parse_basics(void)
{
	/* empty input -> incomplete */
	size_t consumed = 0;
	struct sk_buff *out = NULL;
	assert(control_command_parse((const unsigned char*)"", 0,
				     &consumed, &out) == CONTROL_PARSE_INCOMPLETE);
	assert(consumed == 0 && out == NULL);

	/* fragmented input: no terminator yet -> incomplete */
	assert(control_command_parse((const unsigned char*)"sf 3 /tmp/", 10,
				     &consumed, &out) == CONTROL_PARSE_INCOMPLETE);
	assert(consumed == 0 && out == NULL);

	/* complete command -> ok, native head + payload */
	expect_parse("sf 3 /tmp/out.bin\n", CONTROL_PARSE_OK,
		     strlen("sf 3 /tmp/out.bin\n"),
		     TASK_THEME_SENDFILE, 3, "/tmp/out.bin");

	/* long-form command word + CRLF terminator */
	expect_parse("sendfile 2 /a\r\n", CONTROL_PARSE_OK,
		     strlen("sendfile 2 /a\r\n"),
		     TASK_THEME_SENDFILE, 2, "/a");

	/* perf command, no payload */
	expect_parse("performance 1\n", CONTROL_PARSE_OK,
		     strlen("performance 1\n"),
		     TASK_THEME_PERF, 1, "");
}

static void test_parse_invalid(void)
{
	/* missing space (no serial) */
	expect_parse("sendfile\n", CONTROL_PARSE_INVALID,
		     strlen("sendfile\n"), 0, 0, "");

	/* unknown command */
	expect_parse("bogus 3 /tmp/x\n", CONTROL_PARSE_INVALID,
		     strlen("bogus 3 /tmp/x\n"), 0, 0, "");

	/* probe is a control-stream message, NOT a task command */
	expect_parse("probe 1\n", CONTROL_PARSE_INVALID,
		     strlen("probe 1\n"), 0, 0, "");

	/* non-numeric serial */
	expect_parse("sf abc /tmp/x\n", CONTROL_PARSE_INVALID,
		     strlen("sf abc /tmp/x\n"), 0, 0, "");

	/* negative serial */
	expect_parse("sf -1 /tmp/x\n", CONTROL_PARSE_INVALID,
		     strlen("sf -1 /tmp/x\n"), 0, 0, "");

	/* out-of-range / overflow serial */
	expect_parse("sf 999 /tmp/x\n", CONTROL_PARSE_INVALID,
		     strlen("sf 999 /tmp/x\n"), 0, 0, "");
	expect_parse("sf 64 /tmp/x\n", CONTROL_PARSE_INVALID,
		     strlen("sf 64 /tmp/x\n"), 0, 0, "");

	/* leading space -> empty command */
	expect_parse(" sf 3 /x\n", CONTROL_PARSE_INVALID,
		     strlen(" sf 3 /x\n"), 0, 0, "");

	/* empty line is skipped (OK with no output), not invalid */
	{
		size_t consumed = 0;
		struct sk_buff *out = NULL;
		assert(control_command_parse((const unsigned char*)"\n", 1,
					     &consumed, &out) == CONTROL_PARSE_OK);
		assert(consumed == 1);
		assert(out == NULL);
	}
}

static void test_parse_multi_and_segmented(void)
{
	const char *buf = "sf 3 /a\nperf 1 x\n";
	size_t len = strlen(buf);
	size_t off = 0, consumed = 0;
	struct sk_buff *out = NULL;

	/* first command */
	assert(control_command_parse((const unsigned char*)buf + off, len - off,
				     &consumed, &out) == CONTROL_PARSE_OK);
	assert(consumed == strlen("sf 3 /a\n"));
	assert(out != NULL);
	assert(((struct upstream_skb_head*)out->head)->serial == 3);
	skb_free(out);
	off += consumed;

	/* second command */
	assert(control_command_parse((const unsigned char*)buf + off, len - off,
				     &consumed, &out) == CONTROL_PARSE_OK);
	assert(consumed == strlen("perf 1 x\n"));
	assert(out != NULL);
	assert(((struct upstream_skb_head*)out->head)->theme == TASK_THEME_PERF);
	skb_free(out);
	off += consumed;

	/* exhausted -> incomplete */
	assert(control_command_parse((const unsigned char*)buf + off, len - off,
				     &consumed, &out) == CONTROL_PARSE_INCOMPLETE);
	assert(consumed == 0);
	assert(out == NULL);

	/* segmented: partial then completed line */
	assert(control_command_parse((const unsigned char*)"sf 1 /p", 8,
				     &consumed, &out) == CONTROL_PARSE_INCOMPLETE);
	assert(control_command_parse((const unsigned char*)"sf 1 /path\n", 11,
				     &consumed, &out) == CONTROL_PARSE_OK);
	assert(out != NULL);
	assert(strcmp((const char*)out->head + sizeof(struct upstream_skb_head),
		      "/path") == 0);
	skb_free(out);
}

static void test_parse_overlong(void)
{
	/* line longer than CONTROL_MAX_LINE without a terminator */
	size_t n = CONTROL_MAX_LINE;
	unsigned char *buf = malloc(n);
	assert(buf != NULL);
	memset(buf, 'a', n);
	size_t consumed = 0;
	struct sk_buff *out = NULL;
	assert(control_command_parse(buf, n, &consumed, &out) ==
	       CONTROL_PARSE_INVALID);
	assert(out == NULL);
	free(buf);

	/* payload longer than CONTROL_MAX_LINE with a terminator */
	size_t big = CONTROL_MAX_LINE + 16;
	unsigned char *bigbuf = malloc(big);
	assert(bigbuf != NULL);
	size_t pre = (size_t)snprintf((char*)bigbuf, big, "sf 3 ");
	memset(bigbuf + pre, 'b', big - pre - 1);
	bigbuf[big - 1] = '\n';
	assert(control_command_parse(bigbuf, big, &consumed, &out) ==
	       CONTROL_PARSE_INVALID);
	assert(out == NULL);
	free(bigbuf);
}

static void test_response_encode(void)
{
	const char *cmd = "sf 7 /tmp/f\n";
	size_t consumed = 0;
	struct sk_buff *skb = NULL;
	assert(control_command_parse((const unsigned char*)cmd, strlen(cmd),
				     &consumed, &skb) == CONTROL_PARSE_OK);
	assert(skb != NULL);

	size_t written = 0;
	unsigned char out[64];

	/* dry run: output == NULL */
	assert(control_response_encode(skb, NULL, 0, &written) == 0);
	assert(written > 0);

	/* actual encode: "/tmp/f" is 6 bytes -> head->length == 7 */
	assert(control_response_encode(skb, out, sizeof(out), &written) == 0);
	assert(strcmp((const char*)out, "\n7 0 7\n") == 0);
	assert(written == strlen("\n7 0 7\n") + 1);

	/* too-small output */
	assert(control_response_encode(skb, out, 4, &written) == -1);
	assert(written == strlen("\n7 0 7\n") + 1);

	/* NULL input */
	assert(control_response_encode(NULL, out, sizeof(out), &written) == -1);

	skb_free(skb);
}

static void test_null_params(void)
{
	const unsigned char *cmd = (const unsigned char*)"sf 3 /x\n";
	size_t consumed = 0;
	struct sk_buff *out = NULL;

	/* NULL consumed -> INVALID, no crash */
	assert(control_command_parse(cmd, strlen((const char*)cmd),
				     NULL, &out) == CONTROL_PARSE_INVALID);
	assert(out == NULL);

	/* NULL output -> INVALID, no crash */
	assert(control_command_parse(cmd, strlen((const char*)cmd),
				     &consumed, NULL) == CONTROL_PARSE_INVALID);

	/* NULL input -> INCOMPLETE, no crash */
	assert(control_command_parse(NULL, 5, &consumed, &out) ==
	       CONTROL_PARSE_INCOMPLETE);
	assert(out == NULL);
}

int main(void)
{
	test_parse_basics();
	test_parse_invalid();
	test_parse_multi_and_segmented();
	test_parse_overlong();
	test_response_encode();
	test_null_params();
	return 0;
}
