#!/usr/bin/perl

##                       iSPA
## // isochronal Surreptitious Prognostication Agent \\ 
##

use warnings;
use strict;
use IO::Zlib;
use Time::Local;
use threads;
use Thread::Queue;

###########################################################
## Script emails addresses if a suspect IP shows up in logs.
## otherwise nothing happens.
my $email_addr = 'email1@work.com,email2@work.com';
my $cc_list = 'SOC@work.com';
## Results are temporarily written out to this file, using the file handle '$fout'.
#my $file_path = '/tmp/iSPA.tmp';
my $file_path = '/tmp/iSPA.tmp.test';
my $fout;
## A flag for letting the email routine know if to send out an error email
my $error_flag = 0;
## Number of hours to look back into PIX logs
my $hours = 2;
## Number of lines to stuff in email per occurance
my $email_log_lines = 50;
## set num concurrent threads
my $worker_threads = 4;
###########################################################


$| = 1;
my %cidr = (
  '10.20.30.40/29'  => 'Range 1',
  '1.2.3.4/27'      => 'Range 2',
  '5.6.7.8/24'      => 'Range 3',
  '9.10.11.12/27'   => 'Range 4',
  '13.14.15.16/26'  => 'Range 5'
);

### which_server - which server is this??
sub which_server
{
  return (qx/uname -n/ =~ /((?:east|west)server)/)[0];
}

### log_calc - calculate hour,day,month,year to generate logfile paths on server
sub log_calc
{
  my( $hour, $day, $month, $year ) = (localtime())[2,3,4,5];

  $year += 1900;    ## y2k-compliant year functions start at year 1900 AD

  my $server = which_server();
  $server = 'east' if( $server eq 'eastserver' );
  $server = 'west' if( $server eq 'westserver' );

  ## determine how far back to start the clock (calculated from hours given)
  my $history_seconds = 60*60*$hours;
  my $log_date_seconds = timelocal( 0,0,$hour,$day,$month,$year );
  my $delta = $log_date_seconds - $history_seconds;

  my @logfiles;
  my $count = 1;

  while( $count <= $hours )
  {
    my $tmp_month = (localtime( $delta ))[4] + 1;  ## localtime() and timelocal() count 0..11
    my $tmp_day = (localtime( $delta ))[3];
    my $tmp_hour = (localtime( $delta ))[2];

    $tmp_month = sprintf( "%02d", $tmp_month );    ## pad single-digit months with a zero
    $tmp_day = sprintf( "%02d", $tmp_day );
    $tmp_hour = sprintf( "%02d", $tmp_hour );

    ## find and grab NET2 log (compressed or not)
    if( -e "/pix/$tmp_month/NET2/$server-NET2-$year-$tmp_month-$tmp_day-$tmp_hour" ) {
      push( @logfiles, "/pix/$tmp_month/NET2/$server-NET2-$year-$tmp_month-$tmp_day-$tmp_hour" );
    }
    elsif( -e "/pix/$tmp_month/NET2/$server-NET2-$year-$tmp_month-$tmp_day-$tmp_hour.gz" ) {
      push( @logfiles, "/pix/$tmp_month/NET2/$server-NET2-$year-$tmp_month-$tmp_day-$tmp_hour.gz" );
    }
    else {
      print $fout "Cannot find log file:\n";
      print $fout "/pix/$tmp_month/NET2/$server-NET2-$year-$tmp_month-$tmp_day-$tmp_hour\[.gz\]\n";
      $error_flag = 1;
    }
    ## find and grab NET1 log (compressed or not)
    if( -e "/pix/$tmp_month/NET1/$server-NET1-$year-$tmp_month-$tmp_day-$tmp_hour" ) {
      push( @logfiles, "/pix/$tmp_month/NET1/$server-NET1-$year-$tmp_month-$tmp_day-$tmp_hour" );
    }
    elsif( -e "/pix/$tmp_month/NET1/$server-NET1-$year-$tmp_month-$tmp_day-$tmp_hour.gz" ) {
      push( @logfiles, "/pix/$tmp_month/NET1/$server-NET1-$year-$tmp_month-$tmp_day-$tmp_hour.gz" );
    }
    else {
      print $fout "Cannot find log file:\n";
      print $fout "/pix/$tmp_month/NET1/$server-NET1-$year-$tmp_month-$tmp_day-$tmp_hour\[.gz\]\n";
      $error_flag = 1;
    }

    $delta += 3600;  ## number of seconds in an hour
    $count++;
  }

  ## remove the current hour's logfiles, as we are only interested in the hour past
  foreach( 1 .. $hours ) {
    shift @logfiles;
  }

print "\n@logfiles";
exit;
  return \@logfiles;
}

### get_input
sub get_input
{
  my %input;

  ## this first if statement is more for testing the code on a specific log
  ## file; giving more than one file as an argument makes things go slow
  if( @ARGV ) {
    foreach( @ARGV ) {
      my $file;
      if( $_ =~ /.*\.gz$/ ) {
        if( ! open( $file, "gzip -dc $_ |" )) {
          print $fout "Error: Cannot open $_\n";
          $error_flag = 1;
        }
      }
      else {
        if( ! open( $file, "< $_" )) {
          print $fout "Error: Cannot open $_\n";
        }
      }
      $input{$_} = \$file;
    }
  }
  else {
    my $tmp_array_ref = $_[0];
    foreach( @{$tmp_array_ref} ) {
      my $file;
      if( $_ =~ /.*\.gz$/ ) {
        if( ! open( $file, "gzip -dc $_ |" )) {
          print $fout "Error: Cannot open $_\n";
          $error_flag = 1;
        }
      }
      else {
        if( ! open( $file, "< $_" )) {
          print $fout "Error: Cannot open $_\n";
        }
      }
      $input{$_} = \$file;
    }
  }

  return \%input;
}

### pull out IP address from logs which indicate an outside address creating
### an inbound connection. IPs are queued into a FIFO-like thread-safe structure
### which is simultaneously being read by the "worker" threads to do comparisons
sub parse
{
  setpriority( 0, $$, 2 );

  my $fh = ${${$_[0]}};
  my $ip_fifo = ${$_[1]};
  my $addr_regex = qr/\D(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;

  while( <$fh> )
  {
    foreach( $_ =~ /$addr_regex/g ) {
      $ip_fifo->enqueue( $_ );
    }
  }

  foreach( 1 .. ($worker_threads*2) ) {
    $ip_fifo->enqueue( 'finish' );  ## alert worker threads to finish
  }

  close $fh;
}

### bitMatch
sub bitMatch
{
  our %lookup = %{$_[0]};  ## ip => [ bin_ip, mask, org ]
  my $ip_fifo = ${$_[1]};
  my $filename = $_[2];
  my %tmp_data;
  my %data;

  ### hashValueSort - helper routine for below
  sub hashValueSort
  {
    $lookup{$a}[1] <=> $lookup{$b}[1];
  }

  ## create two arrays: one of CIDR IPs, one of their masks, both sorted by
  ## ordering the masks from large to small; purpose here is to help speed
  ## comparisons up by grouping together CIDR addys with the same mask, so we
  ## can compare all similar mask groups at the same time, and recalulating the
  ## mask on the log IP less often
  my( @bin_range_ip, @mask );
  foreach( sort hashValueSort (keys %lookup) ) {
    push( @bin_range_ip, $lookup{$_}[0] );
    push( @mask, $lookup{$_}[1] );
  }

  ## main execution point. for each IP that we can pull off the FIFO (which is being fed
  ## by our parsing thread above), split the IP into octets, translate to a 32-bit binary number,
  ## and compare it to each CIDR block by zeroing the non-mask bits, and-ing the network portion
  ## to our CIDR IP (which is also just a network portion), and compare results to see if the
  ## address remains the same (ie. identical network bits)
  while( my $raw_log_ip = $ip_fifo->dequeue )
  {
    if( $raw_log_ip eq 'finish' ) {
      last;
    }
    my @addr = split( /\./, $raw_log_ip );
    my $bin_log_ip = ($addr[0] << 24) | ($addr[1] << 16) | ($addr[2] << 8) | $addr[3];
    my( $result, $bin_log_net );
    my $recent_mask = 0;

    foreach my $iterator ( 0 .. $#bin_range_ip ) {
      if( $recent_mask != $mask[$iterator] ) {
        $bin_log_net = (($bin_log_ip >> (32 - $mask[$iterator])) << abs($mask[$iterator] - 32));
      }
      $result = ($bin_log_net & $bin_range_ip[$iterator]);

      if( $result == $bin_range_ip[$iterator] && $result == $bin_log_net ) {
        $tmp_data{ $raw_log_ip } = $bin_range_ip[$iterator];
        last;
      }
      $recent_mask = $mask[$iterator];
    }
  }

  ## put all the information regarding the CIDR ranges matched back into the structure
  ## before we push it back to the main routine
  foreach my $ip ( keys %lookup ) {
    foreach my $match ( keys %tmp_data ) {
      if( $tmp_data{$match} == $lookup{$ip}[0] ) {
        $data{$match} = [$lookup{$ip}[2], $filename];
      }
    }
  }

  return \%data;
}

### maskCompute
sub maskCompute
{
  my %tmp;
  my( $ip, $mask );

  ## convert each CIDR address into a binary/decimal number for comparison
  ## later on
  foreach my $ele ( keys %cidr ) {
    ( $ip, $mask ) = split( /\//, $ele );
    my @addr = split( /\./, $ip );
    foreach my $pos ( 0 .. $#addr ) {
      $addr[$pos] = $addr[$pos] << (24-($pos*8));
    }

    my $bin_ip = $addr[0] | $addr[1] | $addr[2] | $addr[3];
    my $bin_mask = ( ($bin_ip >> (32 - $mask)) << abs($mask - 32) );

    ## checks are done on each CIDR to make sure it is valid
    if( $bin_ip != $bin_mask ) {
      print $fout "\nBad CIDR IP $ele\n";
      print $fout "Correct and run again\n";
      email( 1 );
    }
    $tmp{ $ip } = [ $bin_ip, $mask, $cidr{ $ele } ];
  }

  return \%tmp;
}

### output
sub output
{
  ## %data: ip => [whois, logfile name]
  my $data = $_[0];
  my $log_pat = qr/^\/pix\//;
  print $fout "Found in logs (last hour):\n\n";

  while( my($ip,$array) = each(%{$data}) ) {
    my @tmp = @$array;
    foreach my $ele ( 1 .. $#tmp ) {
      if( $tmp[$ele] =~ /$log_pat/ ) {
        print $fout "$ip - $tmp[0] - $tmp[$ele]\n\n";
      }
      else {
        print $fout "   -> $tmp[$ele]\n";
      }
    }
    print $fout "\n-----------------\n\n";
  }
}

### email routine for sending messages
sub email
{
  if( $_[0] ) {
    my $server = ucfirst(which_server());
    `cat $file_path | mail -s "iSPA-$server: **Possible SPA Scan**" -c $cc_list $email_addr`;
  }
}

### gather info from log file about IP activity
sub findData
{
  ## %data: ip => [whois, logfile name]
  my $data = $_[0];

  foreach my $ip ( keys %{$data} ) {
    my( $fh, $optimal );

    if( ${$data}{$ip}[1] =~ /.*\.gz$/ ) {
      open( $fh, "gzip -dc ${$data}{$ip}[1] |" );
    }
    else {
      open( $fh, "< ${$data}{$ip}[1]" );
    }

    $optimal = $ip;
    $optimal =~ s/\./\\\./g;
    my $address = qr/\D$optimal\D/;
    my $format = qr/%\S+?:\s+(?(?!.+?[A-Z]{3,4}\sconnection\s\S+?\s)(.+)|(.+?[A-Z]{3,4}\s)connection\s\S+?\s(.+))/;

    while( <$fh> ) {
      if( $_ =~ /$address/ ) {
        my @tmp = ($_ =~ /$format/);
        my $concat;
        foreach my $ele ( @tmp ) {
          if( $ele ) {
            $ele =~ s/\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}\)\s//;
            $concat .= "$ele";
          }
        }
        if( $#{${$data}{$ip}} <= $email_log_lines ) {    ## prevent more than 50 lines being added
          push( @{${$data}{$ip}}, $concat );
        }
      }
    }

    close $fh;
  }
  return $data;
}

### main
sub main
{
  open( $fout, "> $file_path" ) or die "Error: Cannot open $file_path for writing";
  my $logfiles = log_calc();
  my $input = get_input( $logfiles );
  my $lookup = maskCompute();

  my @thr_array;
  my $counter = 0;

  ## set up parsing thread and worker threads to do bitwise IP comparisons;
  ## threads communicate through the thread-safe structure called "$queue"
  foreach my $log ( keys %{$input} ) {
    my $queue = new Thread::Queue;
    threads->create( \&parse, \${$input}{$log}, \$queue );
    foreach( 1 .. $worker_threads ) {
      push( @thr_array, threads->create( \&bitMatch, $lookup, \$queue, $log ) );
    }
  }

  ## retrieve data from threads; check for any IPs found, and put them into
  ## a hash for later use
  my %data;
  my $send_email = 0;
  foreach( @thr_array ) {
    my $ReturnData = $_->join();
    if( %{$ReturnData} ) {
      $send_email = 1;
      foreach my $ip ( keys %{$ReturnData} ) {
        if( ! exists $data{$ip} ) {
          $data{ $ip } = [ ${$ReturnData}{$ip}[0], ${$ReturnData}{$ip}[1] ];
        }
        ## in case the same IP is seen on multiple log files, push
        ## the other path(s) onto the structure for reference
        elsif( ${$data{$ip}}[1] ne ${$ReturnData}{$ip}[1] ) {
          push( @{$data{ $ip }}, ${$ReturnData}{$ip}[1] );
        }
      }
    }
  }

  if( $send_email ) {
    output( findData( \%data ) );
    email( $send_email );
  }

  close( $fout );
  sleep 1;
  if( -e $file_path && -T $file_path ) {
    system( "rm $file_path" );
  }
}

main();
exit;

