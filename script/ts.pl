#!/usr/bin/env perl
use 5.010;

@a = qw / 57.749535620 57.897536059 58.201536961 58.801538737 59.749541540 /;
$cost = $a[-1] - $a[0];
$p = shift @a;
say "Start: ", $p;
for (@a) {
	say $_ - $p;
	$p = $_;
}
say "Costs: ", $cost;
