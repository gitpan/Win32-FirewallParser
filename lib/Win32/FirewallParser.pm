# Win32::FirewallParser - Microsoft Windows XP SP2 Firewall Log Parser
# Copyright (C) 2005-2006 Luke Triantafyllidis
#
# This library is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.

package Win32::FirewallParser;

use strict;
use warnings;
use constant HANDLERS => 0;

our $VERSION = '0.02';

sub new {
	my $class = shift;

	bless [[]], $class;
}

sub setHandler {
	my ($self, $handler) = @_;

	die "CODE handler not specified\n" unless ref $handler eq 'CODE';

	# setHandler overrides any previous callback functions
	$self->[HANDLERS] = [$handler];
}

sub addHandler {
	my ($self, $handler) = @_;

	die "CODE handler not specified\n" unless ref $handler eq 'CODE';

	push @{$self->[HANDLERS]}, $handler;
}

sub removeHandler {
	my ($self, $coderef) = @_;

	map { splice @{$self->[HANDLERS]}, $_, 1 }
		grep { $self->[HANDLERS]->[$_] == $coderef }
			0 .. $#{$self->[HANDLERS]}
}

sub parseFile {
	my $self = shift;
	my $file = shift || $ENV{'SystemRoot'} . '/pfirewall.log';
	my $data = {};

	open my $fh, '<', $file or die "unable to open $file: $!\n";

	while(<$fh>) {
		chomp;
		next if /^(#|$)/; # ignore comments and blank lines

		my ($date, $time, $action, $proto, $from_addr, $to_addr, $from_port, $to_port, $size,
				$tcp_flags, $tcp_syn, $tcp_ack, $tcp_win, $icmp_type, $icmp_code, $info, $path) = split / /;
		$data->{'date'} = $date;
		$data->{'time'} = $time;
		$data->{'action'} = $action;
		$data->{'srcAddr'} = $from_addr;
		$data->{'dstAddr'} = $to_addr;
		$data->{'srcPort'} = $from_port;
		$data->{'dstPort'} = $to_port;
		$data->{'size'} = $size;
		$data->{'tcpFlags'} = $tcp_flags;
		$data->{'tcpSyn'} = $tcp_syn;
		$data->{'tcpAck'} = $tcp_ack;
		$data->{'tcpWin'} = $tcp_win;
		$data->{'icmpType'} = $icmp_type;
		$data->{'icmpCode'} = $icmp_code;
		$data->{'info'} = $info;
		$data->{'path'} = $path;

		map { $_->($data) } @{$self->[HANDLERS]}
	}

	close $fh;
}

1;
