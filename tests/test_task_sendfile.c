#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "task_sendfile.h"

int main(void)
{
	struct task *t = task_create_sendfile(3);
	assert(t != NULL);

	/* callbacks wired to the sendfile family */
	assert(t->init == sendfile_init);
	assert(t->nego == sendfile_nego);
	assert(t->exit == sendfile_exit);

	/* stream 0 is the control stream */
	struct subtask *s0 = task_get_sendfile_sub_at(t, 0);
	assert(s0 != NULL);
	assert(s0->no == 0);
	assert(s0->rx_func == sendfile_ctrl_rx);
	assert(s0->tx_func == sendfile_ctrl_tx);
	assert(s0->done == sendfile_done);
	assert(s0->task == t);

	/* streams 1..n-1 are data streams */
	struct subtask *s1 = task_get_sendfile_sub_at(t, 1);
	assert(s1 != NULL);
	assert(s1->no == 1);
	assert(s1->rx_func == sendfile_rx);
	assert(s1->tx_func == sendfile_tx);

	/* n_sub is set by task_create (the dispatch entry), not by the
	 * entity factory; mirror that before exercising the iterator. */
	t->n_sub = 3;

	/* sequential accessor walks 0,1,2 then NULL */
	struct subtask *a = task_get_sendfile_sub_next(t);
	assert(a == s0);
	struct subtask *b = task_get_sendfile_sub_next(t);
	assert(b == s1);
	assert(task_get_sendfile_sub_next(t) != NULL);   /* stream 2 */
	assert(task_get_sendfile_sub_next(t) == NULL);   /* exhausted */

	/* sendfile_exit must free the nego struct + its strdup'd strings and
	 * the task itself (verified leak-free under the LSan build). */
	struct sendfile_task *sft = container_of(t, struct sendfile_task, task);
	sft->nego = calloc(1, sizeof(*sft->nego));
	assert(sft->nego != NULL);
	sft->nego->path = strdup("/tmp");
	sft->nego->file = strdup("a.txt");
	sft->nego->type = strdup("application/octet-stream");
	assert(sft->nego->path && sft->nego->file && sft->nego->type);
	assert(sendfile_exit(t) == NULL);

	/* A negotiation buffer that is too small must not retain any of the
	 * owned string copies made before encoding. */
	t = task_create_sendfile(2);
	assert(t != NULL);
	t->role = TASK_ROLE_SEND;
	t->n_sub = 2;
	struct upstream_skb_head head = {
		.theme = TASK_THEME_SENDFILE,
		.serial = 1,
	};
	t->data = &head;
	sft = container_of(t, struct sendfile_task, task);
	sft->source_path = strdup("/tmp/a.txt");
	sft->type = strdup("application/octet-stream");
	assert(sft->source_path && sft->type);
	sft->path = "/tmp";
	sft->file = "a.txt";
	sft->length = 1;

	/* Build the chunk plan sendfile_init() would produce (n_sub-1 == 1). */
	struct ace_sendfile_chunk sft_chunks[1] = { { .offset = 0, .size = 1 } };
	sft->chunks = (struct ace_sendfile_chunk*)malloc(sizeof(sft_chunks));
	assert(sft->chunks != NULL);
	memcpy(sft->chunks, sft_chunks, sizeof(sft_chunks));

	struct ace_sendfile_nego expected = {
		.code = 0,
		.path = sft->path,
		.path_len = (uint16_t)(strlen(sft->path) + 1),
		.file = sft->file,
		.file_len = (uint16_t)(strlen(sft->file) + 1),
		.type = sft->type,
		.type_len = (uint16_t)(strlen(sft->type) + 1),
		.file_length = (uint32_t)sft->length,
		.n_segments = 1,
		.chunks = sft_chunks,
	};
	size_t total = ace_sendfile_nego_encode(NULL, 0, head.serial, &expected);
	assert(total > 1);
	struct sk_buff *small = skb_malloc((ssize_t)(total - 1));
	assert(small != NULL);
	assert(sendfile_nego(t, small) == -1);
	assert(sft->nego == NULL);
	skb_free(small);
	assert(sendfile_exit(t) == NULL);

	/* TOCTOU regression: the SEND path snapshots the source into an
	 * immutable, sealed memfd at init time.  A later external write (or
	 * truncate) to the source path must NOT change the bytes the sender
	 * transmits, so the negotiated file_hash stays consistent with the
	 * content (no mixing of old identity + new bytes). */
	{
		char src[] = "/tmp/ace-sf-snap-XXXXXX";
		int sfd = mkstemp(src);
		assert(sfd >= 0);
		const char content[] = "0123456789abcdef";
		size_t clen = sizeof(content) - 1;   /* 16 bytes, no NUL */
		assert(write(sfd, content, clen) == (ssize_t)clen);
		close(sfd);

		/* native head + path payload, exactly as the upstream queue builds */
		struct upstream_skb_head head = {
			.theme = TASK_THEME_SENDFILE,
			.serial = 1,            /* n_sub = serial + 1 = 2 */
		};
		size_t buflen = sizeof(head) + strlen(src) + 1;
		char *cmd = malloc(buflen);
		assert(cmd != NULL);
		memcpy(cmd, &head, sizeof(head));
		memcpy(cmd + sizeof(head), src, strlen(src) + 1);

		t = task_create_sendfile(2);
		assert(t != NULL);
		t->role = TASK_ROLE_SEND;
		t->n_sub = 2;
		t->data = cmd;

		assert(sendfile_init(t) == 0);
		sft = container_of(t, struct sendfile_task, task);
		assert(sft->length == clen);
		assert(sft->data != NULL);
		assert(memcmp(sft->data, content, clen) == 0);
		assert(sft->file_hash == task_checksum32(content, clen));
		/* The snapshot memfd must be genuinely sealed read-only (read
		 * back via F_GET_SEALS, not just fcntl's return value). */
		assert(sft->snapshot_seals ==
		       (unsigned int)(F_SEAL_WRITE | F_SEAL_SEAL));

		/* External modification of the source after init must not leak
		 * into the snapshot. */
		int wfd = open(src, O_WRONLY | O_TRUNC);
		assert(wfd >= 0);
		const char evil[] = "XXXXXXXXXXXXXXXX";
		assert(write(wfd, evil, sizeof(evil) - 1) ==
		       (ssize_t)(sizeof(evil) - 1));
		close(wfd);

		assert(memcmp(sft->data, content, clen) == 0);
		assert(sft->file_hash == task_checksum32(content, clen));

		assert(sendfile_exit(t) == NULL);
		free(cmd);
		unlink(src);
	}

	/* Empty files are rejected explicitly: there is nothing to transfer and
	 * the receiver's zero-length-segment path cannot complete. */
	{
		char src[] = "/tmp/ace-sf-empty-XXXXXX";
		int sfd = mkstemp(src);
		assert(sfd >= 0);
		close(sfd);   /* zero bytes */

		struct upstream_skb_head head = {
			.theme = TASK_THEME_SENDFILE,
			.serial = 1,
		};
		size_t buflen = sizeof(head) + strlen(src) + 1;
		char *cmd = malloc(buflen);
		assert(cmd != NULL);
		memcpy(cmd, &head, sizeof(head));
		memcpy(cmd + sizeof(head), src, strlen(src) + 1);

		t = task_create_sendfile(2);
		assert(t != NULL);
		t->role = TASK_ROLE_SEND;
		t->n_sub = 2;
		t->data = cmd;

		assert(sendfile_init(t) == -1);   /* empty file rejected */

		/* init failed after freeing its own source_path; exit still cleans
		 * the task (NULL type/chunks are safe to free). */
		assert(sendfile_exit(t) == NULL);
		free(cmd);
		unlink(src);
	}

	/* Files larger than ACE_MAX_FILE_SIZE are rejected with EFBIG.  A sparse
	 * file via ftruncate reports the huge size without touching the disk. */
	{
		char src[] = "/tmp/ace-sf-big-XXXXXX";
		int sfd = mkstemp(src);
		assert(sfd >= 0);
		assert(ftruncate(sfd, (off_t)ACE_MAX_FILE_SIZE + 1) == 0);
		close(sfd);

		struct upstream_skb_head head = {
			.theme = TASK_THEME_SENDFILE,
			.serial = 1,
		};
		size_t buflen = sizeof(head) + strlen(src) + 1;
		char *cmd = malloc(buflen);
		assert(cmd != NULL);
		memcpy(cmd, &head, sizeof(head));
		memcpy(cmd + sizeof(head), src, strlen(src) + 1);

		t = task_create_sendfile(2);
		assert(t != NULL);
		t->role = TASK_ROLE_SEND;
		t->n_sub = 2;
		t->data = cmd;

		errno = 0;
		assert(sendfile_init(t) == -1);   /* oversized file rejected */
		assert(errno == EFBIG);

		assert(sendfile_exit(t) == NULL);
		free(cmd);
		unlink(src);
	}

	/* A basename near (but under) NAME_MAX must NOT be rejected — the
	 * NAME_MAX check is a fail-fast mirror of the receiver's validation and
	 * must not trip on legal long names. */
	{
		char src[300];
		strcpy(src, "/tmp/");
		memset(src + 5, 'a', 200);
		strcpy(src + 5 + 200, ".bin");   /* 204-byte basename < NAME_MAX */
		int sfd = open(src, O_CREAT | O_WRONLY | O_TRUNC, 0600);
		assert(sfd >= 0);
		const char content[] = "0123456789";
		size_t clen = sizeof(content) - 1;
		assert(write(sfd, content, clen) == (ssize_t)clen);
		close(sfd);

		struct upstream_skb_head head = {
			.theme = TASK_THEME_SENDFILE,
			.serial = 1,
		};
		size_t buflen = sizeof(head) + strlen(src) + 1;
		char *cmd = malloc(buflen);
		assert(cmd != NULL);
		memcpy(cmd, &head, sizeof(head));
		memcpy(cmd + sizeof(head), src, strlen(src) + 1);

		t = task_create_sendfile(2);
		assert(t != NULL);
		t->role = TASK_ROLE_SEND;
		t->n_sub = 2;
		t->data = cmd;

		assert(sendfile_init(t) == 0);   /* legal long name accepted */
		assert(sendfile_exit(t) == NULL);
		free(cmd);
		unlink(src);
	}
	return 0;
}
