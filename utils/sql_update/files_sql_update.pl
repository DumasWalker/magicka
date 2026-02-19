#!/usr/bin/env perl

use DBI;

if (@ARGV < 1) {
	print "Usage: ./files_sql_update dbfile.sq3\n";
	exit(0);
}
my $dbfile = $ARGV[0];

sub check_exists {
	my ($needed) = @_;

	my $dsn = "dbi:SQLite:dbname=$dbfile";
	my $user = "";
	my $password = "";
	my $dbh = DBI->connect($dsn, $user, $password, {
   		PrintError       => 0,
   		RaiseError       => 1,
   		AutoCommit       => 1,
   		FetchHashKeyName => 'NAME_lc',
	});

	my $sql = "PRAGMA table_info(files)";
	my $sth = $dbh->prepare($sql);

	my $gotneeded;

	$sth->execute();
	while (my @row = $sth->fetchrow_array) {
		if ($row[1] eq $needed) {
			$gotneeded = 1;
		}
	}

	$dbh->disconnect;
	return $gotneeded;
}

if (check_exists("uploaddate") == 0) {
	print "Column \"uploaddate\" doesn't exist... adding..\n";

        my ($needed) = @_;

        my $dsn = "dbi:SQLite:dbname=$dbfile";
        my $user = "";
        my $password = "";
        my $dbh = DBI->connect($dsn, $user, $password, {
                PrintError       => 0,
                RaiseError       => 1,
                AutoCommit       => 1,
                FetchHashKeyName => 'NAME_lc',
        });

        my $sql = "ALTER TABLE files ADD COLUMN uploaddate INTEGER DEFAULT 0";
	$dbh->do($sql);
	$dbh->disconnect;	
} 
