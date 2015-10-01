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

# Map of numeric grid references to grid square names
Readonly my %UK_GRID => (
	'012' => 'HL', '112' => 'HM', '212' => 'HN', '312' => 'HO', '412' => 'HP', '512' => 'JL', '612' => 'JM',
	'011' => 'HQ', '111' => 'HR', '211' => 'HS', '311' => 'HT', '411' => 'HU', '511' => 'JQ', '611' => 'JR',
	'010' => 'HV', '110' => 'HW', '210' => 'HX', '310' => 'HY', '410' => 'HZ', '510' => 'JV', '610' => 'JW',
	'09'  => 'NA', '19'  => 'NB', '29'  => 'NC', '39'  => 'ND', '49'  => 'NE', '59'  => 'OA', '69'  => 'OB',
	'08'  => 'NF', '18'  => 'NG', '28'  => 'NH', '38'  => 'NJ', '48'  => 'NK', '58'  => 'OF', '68'  => 'OG',
	'07'  => 'NL', '17'  => 'NM', '27'  => 'NN', '37'  => 'NO', '47'  => 'NP', '57'  => 'OL', '67'  => 'OM',
	'06'  => 'NQ', '16'  => 'NR', '26'  => 'NS', '36'  => 'NT', '46'  => 'NU', '56'  => 'OQ', '66'  => 'OR',
	'05'  => 'NV', '15'  => 'NW', '25'  => 'NX', '35'  => 'NY', '45'  => 'NZ', '55'  => 'OV', '65'  => 'OW',
	'04'  => 'SA', '14'  => 'SB', '24'  => 'SC', '34'  => 'SD', '44'  => 'SE', '54'  => 'TA', '64'  => 'TB',
	'03'  => 'SF', '13'  => 'SG', '23'  => 'SH', '33'  => 'SJ', '43'  => 'SK', '53'  => 'TF', '63'  => 'TG',
	'02'  => 'SL', '12'  => 'SM', '22'  => 'SN', '32'  => 'SO', '42'  => 'SP', '52'  => 'TL', '62'  => 'TM',
	'01'  => 'SQ', '11'  => 'SR', '21'  => 'SS', '31'  => 'ST', '41'  => 'SU', '51'  => 'TQ', '61'  => 'TR',
	'00'  => 'SV', '10'  => 'SW', '20'  => 'SX', '30'  => 'SY', '40'  => 'SZ', '50'  => 'TV', '60'  => 'TW',
);

# Auto-flush output
$OUTPUT_AUTOFLUSH = 1;

sub decode_string
{
	my ($str) = @_;

	$str =~ tr/\._/ -/;

	return $str;
}

sub within_uk
{
	my ($lat, $long) = @_;

	return (($lat > 49) && ($lat < 59) && ($long > -8) && ($long < 2));
}

sub valid_square
{
	my ($square) = @_;

	if ($square) {
		return (uc $square ~~ values %UK_GRID)
	}

	return 0;
}

sub lookup_square
{
	my ($east, $north) = @_;

	return "SU";
}


sub process_gridref
{
	my ($gr) = @_;

	$gr = uc $gr;
	$gr =~ tr/.//d;

	# SU 123 456
	if ($gr =~ /^([A-Z][A-Z])(([0-9][0-9]){1,5})$/) {
		my $square = $1;
		my $ref    = $2;

		my $len = (length $ref) / 2;

		my $east  = substr $ref, 0, $len;
		my $north = substr $ref, $len;

		printf "VALID gridref: $square $east $north\n";
		return 1;
	}

	# Could still be fully numeric 439668.1175316
	if ($gr =~ /^([0-9])([0-9]{5})([0-9])([0-9]{5,6})$/) {
		my $east   = $2;
		my $north  = $4;
		my $square = lookup_square ($1, $3);

		if ($square) {
			printf "VALID gridref: $square $east $north\n";
			return 1;
		}
	}

	printf "INVALID gridref: $gr\n";
	return 0;
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
	if (within_uk ($lat, $long) || within_uk ($long, $lat)) {
		printf "VALID decimal: $long, $lat\n";
		return 1;
	}

	printf "INVALID decimal: $data -- $lat $long\n";
	return 0;
}

sub process_degrees
{
	my ($data) = @_;

	$data =~ tr/_/-/;

	# degrees.minutes.decimal
	# 51.45.79.-1.16.14

	if ($data !~ /^(-?\d{1,2})\.(\d{1,2}\.\d{1,2})[.,](-?\d{1,2})\.(\d{1,2}\.\d{1,2})$/) {
		printf "INVALID degrees: $data\n";
		return 0;
	}

	my $lat_deg = $1 * 1.0;
	my $lat_min = $2 * 1.0;
	my $lon_deg = $3 * 1.0;
	my $lon_min = $4 * 1.0;

	if (($lat_min >= 60) || ($lon_min >= 60)) {
		printf "INVALID degrees: $data\n";
		return 0;
	}

	$lat_min /= 60;
	$lon_min /= 60;

	if ($lat_deg > 0) { $lat_deg += $lat_min; } else { $lat_deg -= $lat_min; }
	if ($lon_deg > 0) { $lon_deg += $lon_min; } else { $lon_deg -= $lon_min; }

	if (!within_uk ($lat_deg, $lon_deg) && !within_uk ($lon_deg, $lat_deg)) {
		printf "INVALID degrees: $data\n";
		return 0;
	}

	printf "VALID degrees: %0.6f, %0.6f\n", $lon_deg, $lat_deg;
	return 1;
}

sub process_message
{
	my ($data) = @_;

	$data = decode_string ($data);

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


# main ();
test ();

exit 0;

