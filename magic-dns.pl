#!/usr/bin/perl -w

use strict;
use IO::Socket;
use Devel::Hexdump 'xd';
use Data::Dumper;
use Net::DNS;
use Net::DNS::Packet;

$Data::Dumper::Indent    = 2;
$Data::Dumper::Useqq     = 1;
$Data::Dumper::Quotekeys = 0;
$Data::Dumper::Sortkeys  = 1;

my ($sock, $buf, $host, $MAXLEN, $PORTNO);

$MAXLEN = 1024;
$PORTNO = 50001;

# Auto-flush output
$| = 1;

sub split_name
{
	my ($name) = @_;

	# print "Name:\n";
	# print xd $name;
	# print "\n";

	my $name_len = length ($name);
	my @part_list = ();
	my $part_len = 1;

	for (my $i = 0; $i < $name_len; $i += ($part_len+1)) {
		$part_len = ord (substr ($name, $i, 1));
		my $part = substr ($name, $i+1, $part_len);
		# printf "i = %d\n", $i;
		# printf "\tpart_len = %d\n", $part_len;
		# printf "\tpart     = %s\n", $part;
		push (@part_list, $part);
	}

	return join (".", @part_list);
}

sub decode_name
{
	my ($name) = @_;

	my @part_list = split_name ($name);

	return join (".", @part_list);
}

sub match_grid_ref
{
	my ($name) = @_;

	$name = decode_name ($name);
	print "$name\n";
}


sub main
{
	$sock = IO::Socket::INET->new (
		LocalPort => $PORTNO,
		Proto => 'udp'
	) or die "socket: $@";

	print "DNSMagic: Awaiting UDP messages on port $PORTNO\n";

	while ($sock->recv ($buf, $MAXLEN)) {

		my $packet = new Net::DNS::Packet (\$buf);
		# print Dumper $packet;

		my ($port, $ipaddr) = sockaddr_in ($sock->peername);

		$host = gethostbyaddr ($ipaddr, AF_INET);
		if (!defined $host) {
			$host = "NXDOMAIN";
		}

		$ipaddr = sprintf "%d.%d.%d.%d", unpack ("C4", $ipaddr);

		printf "Client $ipaddr:$port ($host) sent %d bytes\n", length ($buf);

		my ($txn, $flags, $questions, $answers, $auths, $adds, $query, $qtype, $qclass) = unpack ("n6Z*n2", $buf);
		my $f1 = ($flags >> 15) &  1; # Response: Message is a query
		my $f2 = ($flags >> 11) & 15; # Opcode: Standard query (0)
		my $f3 = ($flags >>  9) &  1; # Truncated: Message is not truncated
		my $f4 = ($flags >>  8) &  1; # Recursion desired: Do query recursively
		my $f5 = ($flags >>  6) &  1; # AD bit: Set
		my $f6 = ($flags >>  4) &  1; # Non-authenticated data: Unacceptable
		printf "flags: %d %04d %d %d %d %d\n", $f1, $f2, $f3, $f4, $f5, $f6;

		my $num_quest   = $packet->{"count"}[0];
		my $num_answers = $packet->{"count"}[1];
		my $num_auths   = $packet->{"count"}[2];
		my $num_adds    = $packet->{"count"}[3];

		printf "Questions: %d\n",      $num_quest;
		printf "Answer RRs: %d\n",     $num_answers;
		printf "Authority RRs: %d\n",  $num_auths;
		printf "Additional RRs: %d\n", $num_adds;

		if ($num_quest > 0) {
			my @q = $packet->question;
			my $q1 = @q[0];
			printf "qtype = %s\n", $q1->qtype;
			printf "label = %s\n", $q1->name;
		}

		# print "$qtype:\n";
		# exit;

		match_grid_ref ($query);

		my $reply;
		# print xd $reply; print "\n";

		$packet = new Net::DNS::Packet();
		$packet->header->id($txn);
		# $packet->header->rcode('NXDOMAIN');
		$packet->header->rcode('NOERROR');
		# printf "%s\n", $packet->header->rcode; exit;
		$packet->header->qr(1);
		$packet->header->aa(1);
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
		my $data = $packet->data();
		# print xd $data; print "\n";

		# printf "txn = %s\n", $txn;
		$sock->send ($data);
		# $sock->send ($reply);
		last;
	}
	die "recv: $!";
}


main();

