#!/usr/bin/perl

use Test::More tests => 1;

# Thanks for the tip, Rick
SKIP: {
    eval { require Test::Pod };
    skip "Test::Pod isn't installed. Believe me: the POD is ok!", 1 if $@;

	Test::Pod::pod_file_ok( 'lib/Win32/FirewallParser.pod', 'Valid POD File' );
}

