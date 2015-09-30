#!/usr/bin/perl

use strict;
use warnings;

our $VERSION = 0.1;

use Data::Dumper;
use Devel::Hexdump 'xd';
use Net::DNS;
use Net::DNS::Packet;

my $buf = "\xF5\x5D\x01\x20\x00\x01\x00\x00" .
	  "\x00\x00\x00\x01\x07\x65\x78\x61" .
	  "\x6D\x70\x6C\x65\x03\x63\x6F\x6D" .
	  "\x00\x00\x01\x00\x01\x00\x00\x29" .
	  "\x10\x00\x00\x00\x00\x00\x00\x00";

# print xd $buf;

my $packet = new Net::DNS::Packet (\$buf);

print Dumper $packet;

