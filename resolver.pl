#!/usr/bin/perl

use strict;
use warnings;

use Net::DNS::Nameserver;
use Net::DNS::Resolver::Programmable;
use Net::DNS::Resolver;

my $verbose=1;

sub reply_handler;

my $recursive = Net::DNS::Resolver->new (
	recursive => 1,
	debug => 1,
);

my $sinkhole = Net::DNS::Resolver::Programmable->new (
	records => {
		'example.com' => [
			Net::DNS::RR->new ('example.com.     NS  ns.example.org.'),
			Net::DNS::RR->new ('example.com.     A   192.168.0.1')
		],
		'ns.example.org' => [
			Net::DNS::RR->new ('ns.example.org.  A   192.168.1.1')
		]
	},
);

my $ns = Net::DNS::Nameserver->new (
	LocalPort    => 50001,
	LocalAddr    => ['127.0.0.1', ],
	ReplyHandler => \&reply_handler,
	Verbose      => $verbose,
) || die "couldn't create nameserver object\n";

sub reply_handler {
	my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;
	my ($rcode, @ans, @auth, @add);

	my $question = $sinkhole->query ($qname,$qtype,$qclass);
	@ans = $question->answer();
	$rcode = "NOERROR";
	return ($rcode, \@ans,);

}

$ns->main_loop;

