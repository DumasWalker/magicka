#!/usr/bin/env perl

use DBI;

if (@ARGV < 1) {
	print "Usage: ./user_sql_update dbfile.sq3\n";
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

	my $sql = "PRAGMA table_info(users)";
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

if (check_exists("protocol") == 0) {
	print "Column \"protocol\" doesn't exist... adding..\n";

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

        my $sql = "ALTER TABLE users ADD COLUMN protocol INTEGER DEFAULT 1";
	$dbh->do($sql);
	$dbh->disconnect;	
} 

if (check_exists("archiver") == 0) {
        print "Column \"archiver\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN archiver INTEGER DEFAULT 1";   
	$dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("bwavepktno") == 0) {
        print "Column \"bwavepktno\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN bwavepktno INTEGER DEFAULT 0";   
        $dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("nodemsgs") == 0) {
        print "Column \"nodemsgs\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN nodemsgs INTEGER DEFAULT 1";   
        $dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("codepage") == 0) {
        print "Column \"codepage\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN codepage INTEGER DEFAULT 0";   
        $dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("exteditor") == 0) {
        print "Column \"exteditor\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN exteditor INTEGER DEFAULT 2";   
        $dbh->do($sql);
        $dbh->disconnect;  
}


if (check_exists("bwavestyle") == 0) {
        print "Column \"bwavestyle\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN bwavestyle INTEGER DEFAULT 0";   
        $dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("signature") == 0) {
        print "Column \"signature\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN signature TEXT DEFAULT \"\"";   
        $dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("autosig") == 0) {
        print "Column \"autosig\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN autosig INTEGER DEFAULT 0";   
        $dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("dopipe") == 0) {
        print "Column \"dopipe\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN dopipe INTEGER DEFAULT 0";   
        $dbh->do($sql);
        $dbh->disconnect;  
}

if (check_exists("qwke") == 0) {
        print "Column \"qwke\" doesn't exist... adding..\n"; 

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

        my $sql = "ALTER TABLE users ADD COLUMN qwke INTEGER DEFAULT 0";   
        $dbh->do($sql);
        $dbh->disconnect;  
}
