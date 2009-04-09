# Example code for Win32::FirewallParser

use lib '../lib';
use strict;
use warnings;
use Win32::FirewallParser;

my $obj = new Win32::FirewallParser;

$obj->addHandler( \&printLine );
$obj->addHandler( \&dummyHandler );
$obj->removeHandler( \&dummyHandler );
$obj->parseFile();

sub printLine {
	my $data = shift;

	for my $key ( keys %{$data} ) {
		printf "%10s => %s\n", $key, $data->{$key};
	}

	print "\n";
}

sub dummyHandler {
	print "This is a dummy handler that should never execute :>";
}
