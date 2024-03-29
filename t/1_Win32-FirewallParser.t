use Test::More tests => 5;

BEGIN { use_ok('Win32::FirewallParser') };
require_ok('Win32::FirewallParser');

my $o = new Win32::FirewallParser;
$o->addHandler(\&foo);
ok($o->[0]->[0] == \&foo, '&foo was added to handlers');

$o->addHandler(\&bar);
ok($o->[0]->[1] == \&bar, '&bar was added to handlers');

$o->removeHandler(\&foo);
ok($o->[0]->[0] == \&bar, '&foo was removed from handlers');

sub foo { return; }
sub bar { return; }
