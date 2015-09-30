#!/usr/bin/perl

use strict;
use warnings;

our $VERSION = 0.1;

use Devel::Hexdump 'xd';
use Data::Dumper;
use Net::DNS::RR;

# my $rr = new Net::DNS::RR(
# 	name    => 'example.com',
# 	type    => 'A',
# 	address => '192.0.2.99',
# 	# type    => 'AAAA',
# 	# address => '2a01:7e00::f03c:91ff:fe93:4455'
# );

my $rr = new Net::DNS::RR( name	=> 'name.example.com',
			type	=> 'TXT',
			txtdata => 'single text string'
			);

# $rr = new Net::DNS::RR( name	=> 'name',
# 			type	=> 'TXT',
# 			txtdata => [ 'multiple', 'strings', ... ]
# 			);

my @opaque;
my $offset = 0;
my $data = $rr->encode ($offset, @opaque);

print xd $data;
print "\n";
