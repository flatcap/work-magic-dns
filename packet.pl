#!/usr/bin/perl

use strict;
use warnings;

our $VERSION = 0.1;

use Data::Dumper;
use Net::DNS;
use Net::DNS::Packet;
use Devel::Hexdump 'xd';

# my $reply = $resolver->send( $query );

my $packet;
# $packet = new Net::DNS::Packet( 'example.com', 'NS', 'IN' );
# $packet = new Net::DNS::Packet('flatcap.org');

$packet = new Net::DNS::Packet();
$packet->push(pre => nxdomain("host.example.com"));

my $forg = Net::DNS::RR->new ('flatcap.org. SOA ns.flatcap.org richardrusson.gmail.com 14400 3600 1814400 3600');
# print Dumper @forg;

$packet->push (authority => $forg);
# push @auth, $forg;
# print Dumper @auth;

# print xd $packet;
print Dumper $packet;
# print $packet->string;

# my $data = $packet->data();
# print xd $data;

# my $packet2 = new Net::DNS::Packet( \$data );
# print Dumper $packet2;

