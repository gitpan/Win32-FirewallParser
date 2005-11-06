# Win32::FirewallParser - Microsoft Windows XP SP2 Firewall Log Parser
# Copyright (C) 2005 Luke Triantafyllidis
#
# This library is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.

package Win32::FirewallParser;

use strict;
use warnings;
use Carp;

our $VERSION = '0.01';

sub new
{
	my $class = shift;

	bless {
		handler => undef
	}, $class;
}

sub setHandler
{
	my $self = shift;
	my $handler = shift;

	croak "CODE handler not specified\n" unless ref $handler eq 'CODE';

	$self->{'handler'} = $handler;
}

sub parseFile
{
	my $self = shift;
	my $file = shift || $ENV{'SystemRoot'} . '/pfirewall.log';
	my $data = {};

	die "no handler set\n" unless defined $self->{'handler'};

	open my $fh, '<', $file or croak "unable to open $file: $!\n";

	while(<$fh>)
	{
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

		&{$self->{'handler'}}($data);
	}

	close $fh;
}

1;

__END__

=head1 NAME

Win32::FirewallParser - Microsoft Windows XP SP2 Firewall Log Parser

=head1 SYNOPSIS

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

=head1 DESCRIPTION

Module for parsing Microsoft Windows XP SP2 Firewall log files.

=over 4

=head1 CONSTRUCTOR

=item new ()

No constructor parameters required.

=head1 METHODS

=item setHandler ( HANDLER )

This method sets a handler in which a subroutine can be called per line in
the log file.

The handler subroutine takes one parameter, a hash reference, which
contains the data of the current line that the parser is up to.

=item parseFile ( [FILENAME] )

Start parsing a file. If no parameter is specified, the default log file
path using the environmental variable I<SystemRoot>,
I<%SystemRoot%/pfirewall.log>, will be used.

=back

=head1 AUTHOR

Luke Triantafyllidis <triple@aeoth.net>

=head1 COPYRIGHT

Copyright (C) 2005 Luke Triantafyllidis

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 CHANGELOG

2005-11-07 0.01  Beta release.

=cut
