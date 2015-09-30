#!/usr/bin/perl -w

use strict;
use warnings;

our $VERSION = 0.1;

use IO::Socket;
use Devel::Hexdump 'xd';
use Data::Dumper;
use Net::DNS;
use Net::DNS::Packet;

my ($sock, $buf, $host, $MAXLEN, $PORTNO);

$MAXLEN = 1024;
$PORTNO = 50001;

# Auto-flush output
$| = 1;

sub main
{
	$sock = IO::Socket::INET->new (
		LocalPort => $PORTNO,
		Proto => 'udp'
	) or die "socket: $@";

	print "DNSMagic: Awaiting UDP messages on port $PORTNO\n";

	while ($sock->recv ($buf, $MAXLEN)) {

		my ($port, $ipaddr) = sockaddr_in ($sock->peername);
		$host = gethostbyaddr ($ipaddr, AF_INET) || "NXDOMAIN";
		$ipaddr = sprintf "%d.%d.%d.%d", unpack ("C4", $ipaddr);

		printf "Client $ipaddr:$port ($host) sent %d bytes\n", length ($buf);

		my $packet = new Net::DNS::Packet (\$buf);
		# print Dumper $packet;

		my $header = $packet->header;
		my $id = $header->id;
		printf "id                %d\n", $id;
		printf "opcode            %s\n", $header->opcode;
		printf "message truncated %s\n", $header->tc;
		printf "recursion desired %s\n", $header->rd;
		printf "authoritative     %s\n", $header->ad;
		printf "checking          %s\n", $header->cd;
		print "\n";

		my $num_quest   = $header->qdcount;
		my $num_answers = $header->ancount;
		my $num_auths   = $header->nscount;
		my $num_adds    = $header->arcount;

		printf "Questions:      %d\n", $num_quest;
		printf "Answer RRs:     %d\n", $num_answers;
		printf "Authority RRs:  %d\n", $num_auths;
		printf "Additional RRs: %d\n", $num_adds;
		print "\n";

		if ($num_quest > 0) {
			my @q = $packet->question;
			my $q1 = $q[0];
			printf "qtype = %s\n", $q1->qtype;
			printf "label = %s\n", $q1->name;
		}

		$packet = new Net::DNS::Packet();
		$packet->header->id($id);
		$packet->header->rcode('NOERROR');	# NXDOMAIN SERVFAIL
		my $forg = new Net::DNS::RR (
			name => 'flatcap.org',
			type => 'SOA',
			ttl => '1H',
			mname => 'ns.flatcap.org',
			rname => 'richardrusson@gmail.com',
			serial => '2015092901',
			refresh => '7200',
			retry => '3600',
			expire => '1209600',
			minimum => '3600',
		);

		my $addr = sprintf "%d.%d.%d.%d", rand(256), rand(256), rand(256), rand(256);
		my $ans = new Net::DNS::RR (
			name => 'example.com',
			type => 'A',
			address => $addr
		);

		my $txt = new Net::DNS::RR (
			name => 'txt.example.com',
			type => 'TXT',
			txtdata => "there was an old woman who lived in a shoe"
		);

		my $txt2 = new Net::DNS::RR (
			name => 'txt2.example.com',
			type => 'TXT',
			txtdata => [ "she has so many children", "she didn't know what to do" ]
		);

		$packet->push (authority => $forg);
		my $qu = Net::DNS::Question->new ('example.com');
		$packet->push (question => $qu);
		$packet->push (answer => $ans);
		$packet->push (additional => $txt);
		$packet->push (additional => $txt2);

		$packet->header->qr(1);
		$packet->header->aa(1);
		my $data = $packet->data();
		# print xd $data; print "\n";

		$sock->send ($data);
	}
	die "recv: $!";
}


main();

