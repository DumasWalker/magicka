#!/usr/bin/env perl

use Time::Local;
use DBI;
use strict;

if ($#ARGV) {
    print "Usage ./newfilescan.pl filedb\n";
    exit(0);
}

my $database = $ARGV[0];

my $driver   = "SQLite"; 
my $dsn = "DBI:$driver:dbname=$database";
my $userid = "";
my $password = "";
my $dbh = DBI->connect($dsn, $userid, $password, { RaiseError => 1 }) 
                      or die $DBI::errstr;

my $timestamp = timelocal(0, 0, 0, (localtime)[3,4,5]);
my $sth = $dbh->prepare('SELECT filename, description, size FROM files WHERE uploaddate > $1');
my $rv = $sth->execute($timestamp) or die $DBI::errstr;

my $result;

while ($result = $sth->fetchrow_hashref()){
	my $fname = $result->{filename};
	my $desc = $result->{description};
	my $size = $result->{size};
	
	my @lines = split(/\n/, $desc);
	my $sizech;
	
	if ($size > 1024) {
		$size = $size / 1024;
		$sizech = 'k';
	}

	if ($size > 1024) {
		$size = $size / 1024;
		$sizech = 'M';
	}
	
	if ($size > 1024) {
		$size = $size / 1024;
		$sizech = 'G';
	}	
	my @fnameparts = split(/\//, $fname);
	
	printf "%-25.25s %6d%s %-45.45s\n", $fnameparts[$#fnameparts], $size, $sizech, $lines[0];
	my $i;
	for ($i = 1; $i <= $#lines; $i++) {
		printf "                                  %-45.45s\n", $lines[$i];
	}
	
	printf "\n";
}
