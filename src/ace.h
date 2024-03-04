#ifndef __ACE_H__
#define __ACE_H__

#include "server.h"
#include "client.h"
#include "service.h"
#include "connote.h"
#include "define.h"
#include "list.h"

int ace_init_client();
int ace_init_server();
int ace_connect();

#endif
