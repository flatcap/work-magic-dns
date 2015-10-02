#!/usr/bin/perl

use strict;
use warnings;

our $VERSION = 0.1;

use IO::Socket;
use Net::DNS;
use Net::DNS::Packet;
use Readonly;
use English qw(-no_match_vars);
use Carp;
use feature 'switch';
use POSIX qw(strftime);

use HikeDNS;

# Auto-flush output
$OUTPUT_AUTOFLUSH = 1;

Readonly my $MAXLEN => 1024;
Readonly my $PORTNO => 50_001;

sub make_authority
{
	my $serial = strftime '%Y%m%d01', gmtime;
	my $auth = Net::DNS::RR->new (
		name    => 'flatcap.org',
		type    => 'SOA',
		ttl     => '1H',
		mname   => 'ns.flatcap.org',
		rname   => 'richardrusson@gmail.com',
		serial  => $serial,
		refresh => '7200',
		retry   => '3600',
		expire  => '1209600',
		minimum => '3600',
	);

	return $auth;
}

sub main
{
	my $sock = IO::Socket::INET->new (
		LocalPort => $PORTNO,
		Proto     => 'udp'
	) or croak "socket: $EVAL_ERROR";

	printf "DNSMagic: Awaiting UDP messages on port $PORTNO\n";

	my $domain_auth = make_authority ();

	my $buf;
	while ($sock->recv ($buf, $MAXLEN)) {

		my ($port, $ipaddr) = sockaddr_in ($sock->peername);
		my $host = gethostbyaddr ($ipaddr, AF_INET) || 'NXDOMAIN';
		$ipaddr = sprintf '%d.%d.%d.%d', unpack 'C4', $ipaddr;

		printf "Client $ipaddr:$port ($host) sent %d bytes\n", length $buf;

		my $packet = Net::DNS::Packet->new (\$buf);
		my $header = $packet->header;

		my $reply = $packet->reply ();
		$reply->header->qr (1);

		if (HikeDNS::parse ($packet, $reply)) {
			$reply->header->rcode ('NOERROR');
			$reply->header->aa    (1);
			$reply->push (authority => $domain_auth);
		} else {
			$reply->header->rcode ('NXDOMAIN');
		}

		$sock->send ($reply->data ());
	}
	croak "recv: $ERRNO";
}


exit main ();

