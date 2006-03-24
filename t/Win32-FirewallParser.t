# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Win32-FirewallParser.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 5;
BEGIN { use_ok('Win32::FirewallParser') };
require_ok('Win32::FirewallParser');

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $o = new Win32::FirewallParser;
$o->addHandler(\&foo);
ok($o->[0]->[0] == \&foo, '&foo was added to handlers');

$o->addHandler(\&bar);
ok($o->[0]->[1] == \&bar, '&bar was added to handlers');

$o->removeHandler(\&foo);
ok($o->[0]->[0] == \&bar, '&foo was removed from handlers');

sub foo { return; }
sub bar { return; }
