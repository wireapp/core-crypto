#!/usr/bin/env perl
use strict;
use warnings;

local $/ = undef;   # slurp mode; no input separators -> one big input
$_ = <>;            # read whole input (files on command line, fallback to stdin)

# replace "ignore" code blocks with "text"
s/```ignore/```text/g;
# remove lines with admonition markers
s/^.*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\].*\n//mg;

# handle TOC markers
my $start = "<!-- mdformat-toc start";
my $end   = "<!-- mdformat-toc end -->";

if (index($_, $start) == -1 && index($_, $end) == -1) {
    # both absent → do nothing
}
elsif (index($_, $start) == -1 || index($_, $end) == -1) {
    die "Error: only one TOC marker present\n";
}
else {
    s/$start.*?$end//s;
}

print;
