#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "quic_session.h"

int main(void)
{
	char out[256];
	struct sockaddr_in sa4 = {.sin_family = AF_INET, .sin_port = htons(443)};
	assert(inet_pton(AF_INET, "127.0.0.1", &sa4.sin_addr) == 1);

	/* path with peer + device */
	assert(session_resume_file_path(out, sizeof(out), "/tmp/sess",
			(struct sockaddr *)&sa4, "eth0") == 0);
	assert(strcmp(out, "/tmp/sess/127.0.0.1_443-eth0") == 0);

	/* NULL device -> empty suffix */
	assert(session_resume_file_path(out, sizeof(out), "/tmp/sess",
			(struct sockaddr *)&sa4, NULL) == 0);
	assert(strcmp(out, "/tmp/sess/127.0.0.1_443-") == 0);

	/* NULL path -> error */
	assert(session_resume_file_path(out, sizeof(out), NULL,
			(struct sockaddr *)&sa4, NULL) == -1);

	/* load_sess_resume_info round-trips file content */
	const char *tmpfile = "/tmp/test-sess-resume.bin";
	FILE *f = fopen(tmpfile, "wb");
	assert(f != NULL);
	const char data[] = "resume-data";
	assert(fwrite(data, 1, sizeof(data), f) == sizeof(data));
	fclose(f);

	unsigned char *info = NULL;
	ssize_t n = load_sess_resume_info(tmpfile, &info);
	assert(n == (ssize_t)sizeof(data));
	assert(info != NULL);
	assert(memcmp(info, data, sizeof(data)) == 0);
	free(info);

	/* missing file -> 0 (falls back to 1-RTT), info untouched */
	info = NULL;
	n = load_sess_resume_info("/tmp/does-not-exist-sess.bin", &info);
	assert(n == 0);
	assert(info == NULL);

	unlink(tmpfile);

	return 0;
}
