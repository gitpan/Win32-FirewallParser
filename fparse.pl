#!/usr/bin/perl -w

# Test code for Win32::FirewallParser
# by Luke Triantafyllidis <triple[at]aeoth.net>

use strict;
use Win32::FirewallParser;

my $obj = new Win32::FirewallParser;

$obj->setHandler(\&printLine);
$obj->parseFile();

sub printLine
{
	my $data = shift;

	for my $key (keys %{$data})
	{
		printf "%10s => %s\n", $key, $data->{$key};
	}

	print "\n";
}
