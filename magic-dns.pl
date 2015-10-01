#!/usr/bin/perl -w

use strict;
use warnings;

our $VERSION = 0.1;

use IO::Socket;
use Devel::Hexdump 'xd';
use Data::Dumper;
use Net::DNS;
use Net::DNS::Packet;
use Readonly;
use English qw(-no_match_vars);
use Carp;
use feature 'switch';

no warnings 'experimental::smartmatch';

Readonly my $OCTET    => 256;
Readonly my $MAXLEN   => 1024;
Readonly my $PORTNO   => 50_001;
Readonly my $BASEHOST => 'hike.flatcap.org';

# Auto-flush output
$OUTPUT_AUTOFLUSH = 1;

sub process_data
{
	my ($str) = @_;

	$str =~ tr/\._/ -/;

	return $str;
}


sub process_gridref
{
	my ($data) = @_;
	printf "process_gridref '$data'\n";
	# SU1234
	# SU.12.34
	# SU123456
	# SU.123.456
	# SU12345678
	# SU.1234.5678
	# SU1234567890
	# SU.12345.67890
	# 439668.1175316
}

sub process_decimal
{
	my ($data) = @_;

	$data =~ tr/_/-/;

	# e.g. 51.763245.-1.2690672
	if ($data !~ /^(-?\d{1,2}\.\d{1,7})[.,](-?\d{1,2}\.\d{1,7})$/) {
		printf "INVALID decimal: $data\n";
		return 0;
	}

	my $lat  = $1;
	my $long = $2;

	# Check against bounds of the UK
	if (($lat > 49) && ($lat < 59) && ($long > -8) && ($long < 2)) {
		printf "VALID decimal: $long, $lat\n";
		return 1;
	}

	# Swap the coordinates and try again
	($lat, $long) = ($long, $lat);
	if (($lat > 49) && ($lat < 59) && ($long > -8) && ($long < 2)) {
		printf "VALID decimal: $long, $lat\n";
		return 1;
	}

	printf "INVALID decimal: $data -- $lat $long\n";
	return 0;
}

sub process_degrees
{
	my ($data) = @_;
	printf "process_degrees '$data'\n";
	# 51.45.79._1.16.14
}

sub process_message
{
	my ($data) = @_;

	$data = process_data ($data);

	printf "VALID message: $data\n";
	return 1;
}

sub process_route
{
	my ($data) = @_;

	my $dir = "/mnt/space/hikes/generated/routes/$data";
	if (-d $dir) {
		printf "VALID route: $data\n";
		return 1;
	} else {
		printf "INVALID route: $data\n";
		return 0;
	}
}

sub process_waypoint
{
	my ($data) = @_;

	if ($data =~ /^\d{1,5}$/) {
		printf "VALID waypoint: $data\n";
	} else {
		printf "INVALID waypoint: $data\n";
	}
}


sub parse_request
{
	my ($req) = @_;

	if ($req !~ /^((.+)(\.))*$BASEHOST$/msxi) {
		return;
	}

	if (!defined $1) {
		return (q{}, q{});
	}

	if ($2 =~ /([^.]+)\.(.*)/msx) {
		return (uc $1, $2);
	}

	return (uc $2, '');
}


sub main
{
	my $sock = IO::Socket::INET->new (
		LocalPort => $PORTNO,
		Proto     => 'udp'
	) or croak "socket: $EVAL_ERROR";

	printf "DNSMagic: Awaiting UDP messages on port $PORTNO\n";

	my $buf;
	while ($sock->recv ($buf, $MAXLEN)) {

		my ($port, $ipaddr) = sockaddr_in ($sock->peername);
		my $host = gethostbyaddr ($ipaddr, AF_INET) || 'NXDOMAIN';
		$ipaddr = sprintf '%d.%d.%d.%d', unpack 'C4', $ipaddr;

		printf "Client $ipaddr:$port ($host) sent %d bytes\n", length $buf;

		my $packet = Net::DNS::Packet->new (\$buf);
		# print Dumper $packet;

		my $header = $packet->header;
		my $id     = $header->id;
		printf "id                %d\n", $id;
		printf "opcode            %s\n", $header->opcode;
		printf "message truncated %s\n", $header->tc;
		printf "recursion desired %s\n", $header->rd;
		printf "authoritative     %s\n", $header->ad;
		printf "checking          %s\n", $header->cd;
		printf "\n";

		my $num_quest   = $header->qdcount;
		my $num_answers = $header->ancount;
		my $num_auths   = $header->nscount;
		my $num_adds    = $header->arcount;

		printf "Questions:      %d\n", $num_quest;
		printf "Answer RRs:     %d\n", $num_answers;
		printf "Authority RRs:  %d\n", $num_auths;
		printf "Additional RRs: %d\n", $num_adds;
		printf "\n";

		if ($num_quest > 0) {
			my @q  = $packet->question;
			my $q1 = $q[0];
			printf "qtype = %s\n", $q1->qtype;
			printf "label = %s\n", $q1->name;

			my ($type, $data) = parse_request ($q1->name);
			printf "%s, %s\n", $type, $data;
		}

		$packet = Net::DNS::Packet->new ();
		$packet->header->id ($id);
		$packet->header->rcode ('NOERROR');    # NXDOMAIN SERVFAIL
		my $forg = Net::DNS::RR->new (
			name    => 'flatcap.org',
			type    => 'SOA',
			ttl     => '1H',
			mname   => 'ns.flatcap.org',
			rname   => 'richardrusson@gmail.com',
			serial  => '2015092901',
			refresh => '7200',
			retry   => '3600',
			expire  => '1209600',
			minimum => '3600',
		);

		my $addr = sprintf '%d.%d.%d.%d', rand $OCTET, rand $OCTET, rand $OCTET, rand $OCTET;
		my $ans = Net::DNS::RR->new (
			name    => 'example.com',
			type    => 'A',
			address => $addr
		);

		my $txt = Net::DNS::RR->new (
			name    => 'txt.example.com',
			type    => 'TXT',
			txtdata => 'there was an old woman who lived in a shoe'
		);

		my $txt2 = Net::DNS::RR->new (
			name    => 'txt2.example.com',
			type    => 'TXT',
			txtdata => ['she has so many children', 'she didn\'t know what to do']
		);

		$packet->push (authority => $forg);
		my $qu = Net::DNS::Question->new ('example.com');
		$packet->push (question   => $qu);
		$packet->push (answer     => $ans);
		$packet->push (additional => $txt);
		$packet->push (additional => $txt2);

		$packet->header->qr (1);
		$packet->header->aa (1);
		my $data = $packet->data ();
		# print xd $data; print "\n";

		$sock->send ($data);
	}
	croak "recv: $ERRNO";
}

sub test
{
	my $str = $ARGV[0];
	my ($type, $data) = parse_request ($str);

	if (!defined $type || !defined $data) {
		printf "no match\n";
		exit 1;
	}

	# printf ">>%s<< >>%s<<\n", $type, $data;

	given ($type) {
		when ('GR')    { process_gridref  ($data); }
		when ('DEG')   { process_degrees  ($data); }
		when ('DEC')   { process_decimal  ($data); }
		when ('MSG')   { process_message  ($data); }
		when ('ROUTE') { process_route    ($data); }
		when ('WP')    { process_waypoint ($data); }
		default {
			printf "Unknown command: $type\n";
			exit 1;
		}
	}
}


main ();
# test ();

exit 0;

