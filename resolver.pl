#!/usr/bin/perl

use strict;
use warnings;

use Net::DNS::Nameserver;
use Net::DNS::Resolver::Programmable;
use Net::DNS::Resolver;
use Devel::Hexdump 'xd';
use Data::Dumper;

my $verbose = 1;

sub reply_handler {
	my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;
	my ($rcode, @ans, @auth, @add);

	my @ans = Net::DNS::RR->new ('wibble.hatstand.new. A 3.1.4.1');
	# print Dumper @ans;

	# $packet = new Net::DNS::Packet();
	# $packet->push(pre => nxdomain("apple.banana.com"));

	$rcode = "NOERROR";
	return ($rcode, \@ans);
}


my $recursive = Net::DNS::Resolver->new (
	recursive => 1,
	debug => 1,
);

my $ns = Net::DNS::Nameserver->new (
	LocalPort    => 50001,
	LocalAddr    => [ '127.0.0.1' ],
	ReplyHandler => \&reply_handler,
	Verbose      => $verbose,
) || die "couldn't create nameserver object\n";

$ns->main_loop;

