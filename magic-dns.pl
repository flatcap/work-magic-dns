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
use POSIX qw(strftime);

no warnings 'experimental::smartmatch';

Readonly my $OCTET           => 256;
Readonly my $MAXLEN          => 1024;
Readonly my $PORTNO          => 50_001;
Readonly my $BASEHOST        => 'hike.flatcap.org';
Readonly my $MINS_PER_DEGREE => 60;

Readonly my $UK_NORTH => 59;
Readonly my $UK_SOUTH => 49;
Readonly my $UK_EAST  => 2;
Readonly my $UK_WEST  => -8;

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

	$str =~ tr/._/ -/;

	return $str;
}

sub within_uk
{
	my ($lat, $long) = @_;

	return (($lat > $UK_SOUTH) && ($lat < $UK_NORTH) && ($long > $UK_WEST) && ($long < $UK_EAST));
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

	my $index = "$east$north";

	return ($UK_GRID{$index} || q{});
}


sub process_gridref
{
	my ($gr) = @_;

	$gr = uc $gr;
	$gr =~ tr/.//d;

	# SU 123 456
	if ($gr =~ /^([[:upper:]][[:upper:]])((\d\d){1,5})$/msx) {
		my $square = $1;
		my $ref    = $2;

		my $len = (length $ref) / 2;

		my $east = substr $ref, 0, $len;
		my $north = substr $ref, $len;

		printf "VALID gridref: $square $east $north\n";
		return 1;
	}

	# Could still be fully numeric 439668.1175316
	if ($gr =~ /^(\d)(\d{5})(\d)(\d{5,6})$/msx) {
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

	my $lat;
	my $long;

	# e.g. 51.763245.-1.2690672
	if ($data =~ /^(-?\d{1,2}[.]\d{1,7})[.,](-?\d{1,2}[.]\d{1,7})$/msx) {
		$lat  = $1;
		$long = $2;
	} else {
		printf "INVALID decimal: $data\n";
		return 0;
	}

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

	my $lat_deg;
	my $lat_min;
	my $lon_deg;
	my $lon_min;

	Readonly my $RE_DEG => '(-?\d{1,2})[.](\d{1,2}[.]\d{1,2})';
	if ($data =~ /^$RE_DEG[.,]$RE_DEG$/msx) {
		$lat_deg = $1 * 1.0;
		$lat_min = $2 * 1.0;
		$lon_deg = $3 * 1.0;
		$lon_min = $4 * 1.0;
	} else {
		printf "INVALID degrees: $data\n";
		return 0;
	}

	if (($lat_min >= $MINS_PER_DEGREE) || ($lon_min >= $MINS_PER_DEGREE)) {
		printf "INVALID degrees: $data\n";
		return 0;
	}

	$lat_min /= $MINS_PER_DEGREE;
	$lon_min /= $MINS_PER_DEGREE;

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

	if ($data =~ /^\d{1,5}$/msx) {
		printf "VALID waypoint: $data\n";
		return 1;
	} else {
		printf "INVALID waypoint: $data\n";
		return 0;
	}
}


sub parse_request
{
	my ($req) = @_;

	my $sub;
	my $key;

	if ($req =~ /^((.+)([.]))*$BASEHOST$/msxi) {
		$sub = $1;
		$key = $2;
	} else {
		return;
	}

	if (!$sub) {
		return (q{}, q{});
	}

	if ($key =~ /([^.]+)[.](.*)/msx) {
		return (uc $1, $2);
	}

	return (uc $key, q{});
}

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

		my $label = q{};
		if ($header->qdcount > 0) {
			my @q  = $packet->question;
			my $q1 = $q[0];
			# printf "qtype = %s\n", $q1->qtype;
			# printf "label = %s\n", $q1->name;
			$label = $q1->name;

			my ($type, $data) = parse_request ($q1->name);
			# printf "%s, %s\n", $type, $data;

			if (defined $type && defined $data) {
				given ($type) {
					when ('GR')    { process_gridref  ($data); }
					when ('DEG')   { process_degrees  ($data); }
					when ('DEC')   { process_decimal  ($data); }
					when ('MSG')   { process_message  ($data); }
					when ('ROUTE') { process_route    ($data); }
					when ('WP')    { process_waypoint ($data); }
					default {
						printf "Unknown command: $type\n";
					}
				}
			}
		}

		my $reply = $packet->reply ();
		$reply->header->qr (1);

		if ($label =~ /$BASEHOST$/) {
			$reply->header->rcode ('NOERROR');
			my $addr = sprintf '%d.%d.%d.%d', rand $OCTET, rand $OCTET, rand $OCTET, rand $OCTET;
			my $ans = Net::DNS::RR->new (
				name    => $label,
				type    => 'A',
				address => $addr
			);

			$reply->header->aa (1);
			$reply->push (authority => $domain_auth);
			$reply->push (answer => $ans);
		} else {
			$reply->header->rcode ('NXDOMAIN');
		}

		$sock->send ($reply->data ());
	}
	croak "recv: $ERRNO";
}


return main ();

