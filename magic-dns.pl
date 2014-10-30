#!/usr/bin/perl -w

use strict;
use IO::Socket;
use Devel::Hexdump 'xd';
use Data::Dumper;

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

sub encode_name
{
	my ($name) = @_;

	# print "$name\n";
	my @parts = split ('\.', $name);

	# print Dumper (@parts);
	# printf "len = %d\n", scalar @parts;

	my $reply;
	foreach (@parts) {
		$reply .= chr (length ($_));
		$reply .= $_;
	}

	return $reply;
}

sub dump_request
{
	my ($buf) = @_;

	my ($txn, $flags, $questions, $answers, $auths, $adds, $query, $qtype, $qclass) = unpack ("n6Z*n2", $buf);
	my $f1 = ($flags >> 15) &  1;
	my $f2 = ($flags >> 11) & 15;
	my $f3 = ($flags >>  9) &  1;
	my $f4 = ($flags >>  8) &  1;
	my $f5 = ($flags >>  6) &  1;
	my $f6 = ($flags >>  4) &  1;

	print xd $buf;
	printf "Request:\n";
	printf "\ttxn id\t= 0x%04x\n", $txn;
	printf "\tflags\t = 0x%04x\n", $flags;
	printf "\t\tresponse  = %d\n", $f1;
	printf "\t\topcode    = %d\n", $f2;
	printf "\t\ttruncated = %d\n", $f3;
	printf "\t\trecurse   = %d\n", $f4;
	printf "\t\treserved  = %d\n", $f5;
	printf "\t\tnon-auth  = %d\n", $f6;
	printf "\tquestions = %d\n",   $questions;
	printf "\tanswers   = %d\n",   $answers;
	printf "\tauths     = %d\n",   $auths;
	printf "\tadds      = %d\n",   $adds;
	printf "\tquery\n";
	printf "\t\tname  = %s\n",     decode_name ($query);
	printf "\t\ttype  = %d\n",     $qtype;
	printf "\t\tclass = %d\n",     $qclass;
	print "\n";
}

sub match_grid_ref
{
	my ($name) = @_;

	$name = decode_name ($name);
	print "$name\n";
}


sub dns_header
{
	# my ($txn, $flags, $questions, $answers, $auths, $adds) = @_;
	# my $bytes = pack ("n6", $txn, $flags, $questions, $answers, $auths, $adds);
	# return $bytes;
	return pack ("n6", @_);
}

sub dns_query
{
	# my ($query, $qtype, $qclass) = @_;
	# my $bytes = pack ("Z*n2", $query, $qtype);
	# return $bytes;
	return pack ("Z*n2", @_);
}

sub dns_answer
{
	# my ($name_ref, $qtype, $qclass, $ttl, $data_len, $addr) = @_;
	# my $bytes = pack ("n3NnN", $name_ref, $qtype, $qclass, $ttl, $data_len, $addr);
	# return $bytes;

	return pack ("n3NnN", @_);
}

sub dns_authority
{
	my $domain  = encode_name ("flatcap.org");
	my $server  = encode_name ("ns1.flatcap.org");
	my $mail    = encode_name ("richardrusson.gmail.com");
	my $type    = 0x0006;	# SOA
	my $class   = 0x0001;	# IN
	my $ttl     = 86400;	# 1 day
	my $datalen = 22 + length ($server) + length ($mail);
	my $serial  = 2014102001;
	my $refresh = 14400;	# 4 hours
	my $retry   = 14400;	# 4 hours
	my $expire  = 1209600;	# 14 days
	my $minttl  = 86400;	# 1 day

	return pack ("Z*nnNnZ*Z*N5",
		$domain, $type, $class, $ttl, $datalen, $server, $mail, $serial,
		$refresh, $retry, $expire, $minttl);
}


sub main
{
	$sock = IO::Socket::INET->new (
				LocalPort => $PORTNO,
				Proto => 'udp'
				)
				or die "socket: $@";

	print "DNSMagic: Awaiting UDP messages on port $PORTNO\n";

	while ($sock->recv ($buf, $MAXLEN)) {

		my ($port, $ipaddr) = sockaddr_in ($sock->peername);

		$host = gethostbyaddr ($ipaddr, AF_INET);
		if (!defined $host) {
			$host = "";
		}

		$ipaddr = sprintf "%d.%d.%d.%d", unpack ("C4", $ipaddr);

		# printf "Client $ipaddr:$port ($host) sent %d bytes\n", length ($buf);

		my ($txn, $flags, $questions, $answers, $auths, $adds, $query, $qtype, $qclass) = unpack ("n6Z*n2", $buf);
		my $f1 = ($flags >> 15) &  1;
		my $f2 = ($flags >> 11) & 15;
		my $f3 = ($flags >>  9) &  1;
		my $f4 = ($flags >>  8) &  1;
		my $f5 = ($flags >>  6) &  1;
		my $f6 = ($flags >>  4) &  1;

		# print "$qtype: ";
		match_grid_ref ($query);

		# dump_request ($buf);

		my $reply;
		if ($qtype == 1) {		# A record
			# 1.2.3.4
			$answers     = 1;
			if ($answers) {
				$flags = 0b1000010100000000;
			} else {
				$flags = 0b1000010100000011;
			}
			$auths       = 0;
			$adds        = 0;
			my $name_ref = 0xC00C;
			my $ttl      = 60;
			my $data_len = 4;
			my $addr     = (rand(256) << 24) + (rand(256) << 16) + (rand(256) << 8) + rand(256);

			$reply  = dns_header    ($txn, $flags, $questions, $answers, $auths, $adds);
			$reply .= dns_query     ($query, $qtype, $qclass);
			if ($answers) {
				$reply .= dns_answer ($name_ref, $qtype, $qclass, $ttl, $data_len, $addr);
			}
			if ($auths) {
				$reply .= dns_authority ();
			}
			
			if ($adds) {
				$reply .= chr(0x00);	# null string
				$reply .= chr(0x00);	# RR 41 (Option)
				$reply .= chr(0x29);
				$reply .= chr(0x04);	# Payload size 0x400 (1024 bytes)
				$reply .= chr(0x00);
				$reply .= chr(0x00);
				$reply .= chr(0x00);
				$reply .= chr(0x00);
				$reply .= chr(0x00);
				$reply .= chr(0x00);
				$reply .= chr(0x00);
			}
		} elsif ($qtype == 28) {	# AAAA record
			# NXDOMAIN
			$flags = 0b1000010110000011;
			$reply = dns_header ($txn, $flags, $questions, $answers, $auths, $adds);
			$reply .= pack ("Z*n2", $query, $qtype, $qclass);
		} elsif ($qtype == 15) {	# MX record
			# NXDOMAIN
			$flags = 0b1000010110000011;
			$reply = dns_header ($txn, $flags, $questions, $answers, $auths, $adds);
			$reply .= pack ("Z*n2", $query, $qtype, $qclass);
		} else {
		}

		# print xd $reply;
		# print "\n";

		$sock->send ($reply);
	}
	die "recv: $!";
}


main();

