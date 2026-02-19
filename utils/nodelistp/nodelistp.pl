#!/usr/bin/env perl

# Contains code by Robert James Clay's FTNDB project. Licensed under the 
# same license as perl.
# https://metacpan.org/source/JAME/App-FTNDB-0.39/bin/ftndb-nodelist

use DBI;
use strict;

if ($#ARGV < 2) {
    print "Usage ./nodelistp.pl nodelist database.sq3 domain\n";
    exit(0);
}

my $nodelist = $ARGV[0];
my $database = $ARGV[1];
my $domain = $ARGV[2];

my $driver   = "SQLite"; 
my $dsn = "DBI:$driver:dbname=$database";
my $userid = "";
my $password = "";
my $dbh = DBI->connect($dsn, $userid, $password, { RaiseError => 1 }) 
                      or die $DBI::errstr;

my $stmt = qq(CREATE TABLE IF NOT EXISTS nodelist (
						Id INTEGER PRIMARY KEY,
						domain TEXT COLLATE NOCASE,
						nodeno TEXT,
						sysop TEXT,
						location TEXT,
						bbsname TEXT););
my $rv = $dbh->do($stmt);

if($rv < 0){
   print $DBI::errstr;
   exit(0);
} 


open NODELIST, $nodelist or die print "Cannot open $nodelist";

$stmt = 'DELETE FROM nodelist WHERE domain=$1;';
my $sth = $dbh->prepare( $stmt );
$rv = $sth->execute($domain) or die $DBI::errstr;
if($rv < 0){
    print $DBI::errstr;
}
my $nodelistcount = 0;
my $zone   = 1;
my $net    = 0;
my $node   = 0;
my $region = 0;
my $location;
my $sysop;
my $name;
my $type;
my $number;
my $phone;
my $bps;
my $flags;
my $zone_number;
my $nodeno;

while (<NODELIST>) {
    if ( /^;/ || /^\cZ/ ) {
 
        #       print;
        next;
    }
 
    ( $type, $number, $name, $location, $sysop, $phone, $bps, $flags ) =
        split /,/, $_, 8 ;
 
    # if $flags is undefined (i.e., nothing after the baud rate)
    if ( !defined $flags ) {
        $flags = q{ };
    }
    else {
        $flags =~ s/\r?\n$//;    # else remove EOL (removes \r\n or \n but not \r) from $flags
    }
 
    if ( $type eq 'Zone' ) {    # Zone line
        $zone = $number;
        $net  = $number;
        $node = 0;
    }    #
    elsif ( $type eq 'Region' ) {    # Region line
        $region = $number;
        $net    = $number;
        $node   = 0;
    }
    elsif ( $type eq 'Host' ) {      # Host line
        $net  = $number;
        $node = 0;
    }
    else {
        $node = $number;
    }
 
    # If zone_number is defined, then go to the next line if the zone
    # number is not the same as zone_number 
    if (defined $zone_number) {
        if ($zone != $zone_number) {
        next;
        }
    }

    $name =~ s/\_/ /g;
    $sysop =~ s/\_/ /g;
    $location =~ s/\_/ /g;
 
    $nodeno = "$zone:$net/$node";


    $sth = $dbh->prepare('INSERT INTO nodelist (domain, nodeno, sysop, location, bbsname) VALUES($1, $2, $3, $4, $5)');
    $sth->execute($domain, $nodeno, $sysop, $location, $name);

    $nodelistcount++;
}

close NODELIST;

print "Processed $nodelistcount nodes.\n";