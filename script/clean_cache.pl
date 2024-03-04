#!/usr/bin/env perl
use 5.010;

# rm -fr ../skeylog/*
@a = glob("../skeylog/*");
if (@a) {
	for (@a) {
		unlink;
	}
	say("deleted server cached keys ", $#a + 1, "\n");
} else {
	say("no server cached keys\n");
}

# rm -fr ../ckeylog/*
@a = glob("../ckeylog/*");
if (@a) {
	for (@a) {
		unlink;
	}
	say("deleted client cached keys ", $#a + 1, "\n");
} else {
	say("no client cached keys\n");
}

# rm -fr ../session/*
@a = glob("../session/*");
if (@a) {
	for (@a) {
		say;
		unlink;
	}
	say("deleted 0-RTT cache " , $#a + 1, "\n");
} else {
	say("no 0-RTT cache\n");
}
