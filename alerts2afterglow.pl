#!/usr/bin/perl
#
# alerts2afterglow.pl - Script to generate an AfterGlow input from based on OSSEC alerts.
#
# Contact: xavier(at)rootshell(dot)be
#
# History
# -------
# 2011/10/24	Created
# 2011/12/22	Changed the way a given time interval can be processed
#

use strict;
use Getopt::Long;
use DBI;
use Socket;
use Date::Parse;

my $i;
my %records;
my $key;
my $counter = 0;
my $duplicate = 0;
my $source;
my $debug;
my $help;
my $dbName = "ossec";
my $dbHost = "127.0.0.1";
my $dbPort = "3306";
my $dbUser = "ossec";
my $dbPass;
my $doReverse = 0;
my $excludeAlerts = "";
my $showDuplicate = 0;
my $startTime = "";
my $endTime = "";

my $result = GetOptions(
	"debug"			=> \$debug,
	"help"			=> \$help,
	"dbname=s"		=> \$dbName,
	"dbhost=s"		=> \$dbHost,
	"dbuser=s"		=> \$dbUser,
	"dbpass=s"		=> \$dbPass,
	"do-reverse"		=> \$doReverse,
	"exclude-alerts=s"	=> \$excludeAlerts,
	"start-time=s"		=> \$startTime,
	"end-time=s"		=> \$endTime,
	"show-duplicate"	=> \$showDuplicate
);

# Display some (useful) help
if ($help) {
	print <<_HELP_;
Usage: $0 --dbpass=password [--dbhost=127.0.0.1] [--dbport=3306] [--dbname=ossec]
          [--dbuser=ossec] [--exclude-alerts=id1[,id2,...]] [--start-time=timestamp]
          [--end-time=timestamp] [--do-reverse] [--show-duplicate] [--help] [--debug]
_HELP_
	exit 0;
}

$debug && print STDERR "Running in debug mode.\n";

# Check/Sanitize passed command line args
if ($dbPass eq "") {
	print STDERR "No DB pasword provided!\n";
	exit 1;
}

my $dsn = "DBI:mysql:$dbName:$dbHost:$dbUser";
$debug && print STDERR "Connection to $dsn\n";
my $dbh = DBI->connect($dsn, $dbUser, $dbPass) || \
	die "Could not connect to database: $DBI::errstr";

my $query = 'select alert.timestamp, alert.src_ip, signature.description, location.name from alert, location,signature where location.id = alert.location_id and signature.rule_id=alert.rule_id';
if ($excludeAlerts ne "") {
	my @ids = split(",", $excludeAlerts);
	my $id;
	foreach $id(@ids) {
		if (!($id =~ /^\d+$/)) {
			print STDERR "Incorrect alert ID: $id\n";
			exit 1;
		}
	}
	$debug && print STDERR "Excluded alert IDs: $excludeAlerts\n";
	$query = $query . ' and alert.rule_id not in (' . $excludeAlerts . ')';
}

# Process the time interval
# Supported timestamps are: "yyyy/mm/dd hh:mm:ss" or UNIX epoch format
if ($startTime eq "") {
	# Default: startTime is now() - 30 minutes
	$startTime = time() - 1800;
}
else {
	if (!($startTime =~ /^\d+$/)) {
		# Convert to epoch format
		$startTime = str2time($startTime);
	}
	if (time() <= $startTime) {
		print STDERR "start time cannot be in the future\n";
		exit 1;
	}
}
if ($endTime ne "") {
	if (!($endTime =~ /^\d+$/)) {
		# Convert to epoch format
		$endTime = str2time($endTime);
	}
	if ($startTime >= $endTime) {
		print STDERR "start time must be smaller then end time\n";
		exit 1;
	}
	$debug && print STDERR "Time interval: $startTime to $endTime\n";
	$query = $query . ' and alert.timestamp >= "'. $startTime .'" and alert.timestamp <= "' . $endTime . '"';
}
else {
	$debug && print STDERR "Time interval: $startTime to NOW\n";
	$query = $query . ' and alert.timestamp >= "'. $startTime .'"';
}

print "DEBUG: $query\n";
my $sth = $dbh->prepare($query . ";");
$sth->execute();
my ($alertTimeStamp, $alertSrcIP, $sigDesc, $locationName);
while( ($alertTimeStamp, $alertSrcIP, $sigDesc, $locationName) = $sth->fetchrow_array())
{
	# We need a valid source IP address
	if ($alertSrcIP) 
	{
		$key = $alertSrcIP . $sigDesc . $locationName;
		# New event detected, insert a new record
		if (! $records{$key} || $showDuplicate) {
			# Perform DNS reverse lookup?
			if ($doReverse) {
				$source = ReverseLookup(int2ip($alertSrcIP));
			}
			else {
				$source = int2ip($alertSrcIP);
			}
			my @newrecord = ( $source,
					  $sigDesc,
					  $locationName );
			$records{$key} = [ @newrecord ];
			$counter++;
		}
		else {
			# Duplicate record
			$duplicate++;
		}
	}
}

$dbh->disconnect();

for $key ( keys %records) {
	for $i (0 .. $#{ $records{$key} } ) {
		($i > 0) && print ",";
		print $records{$key}[$i];
	}
	print "\n";
}
$debug && print STDERR "Statistics: $counter lines processed ($duplicate duplicates found)\n";
exit 0;

sub int2ip
{
	return inet_ntoa( pack 'N', shift );
}

sub ReverseLookup() {
	my $iaddr = inet_aton(shift);
	return gethostbyaddr($iaddr, AF_INET);
}

# Eof
