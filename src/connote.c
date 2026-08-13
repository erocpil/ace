#include "connote.h"
#include "packet_io.h"

struct connote *connote_init(struct co_config *cc)
{
	struct connote *ce = (struct connote*)malloc(sizeof(struct connote));
	if (!ce) {
		return NULL;
	}
	memset(ce, 0, sizeof(*ce));
	ce->fd = -1;
	ce->cc = cc;
	INIT_LIST_HEAD(&ce->connote_node);

	if (!cc) {
		/* this is a client conn to server */
		return ce;
	}

	switch (cc->flags) {
		case 0:
			if (-1 == connote_init_client(ce)) {
				elog();
				goto ERROR;
			}
			break;
		case 1:
			if (-1 == connote_init_server(ce)) {
				elog();
				goto ERROR;
			}
			break;
		default:
			goto ERROR;
			break;
	}

	// cc->flags |= (unsigned long)ce;
	clog("fd %d", ce->fd);
	return ce;

ERROR:
	connote_free(ce);
	errno = 1;
	return NULL;
}

void connote_free(struct connote *ce)
{
	if (ce->fd > 0) {
		close(ce->fd);
	}
#if 0
	if (ce->keylog_file) {
		fclose(ce->keylog_file);
		ce->keylog_file = NULL;
	}
#endif
	ce->cc = NULL;
	free(ce);
}
