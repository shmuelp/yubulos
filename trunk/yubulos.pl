#!/usr/bin/perl

# Copyright 2009 Shmuel Popper <shmuelp@saraandshmuel.com>
#
# Released as LGPL (http://www.gnu.org/licenses/lgpl.html)

use warnings;
use strict;
use Crypt::Rijndael;

my $confirmArgs=1;

sub usage()
{
    print <<"USAGE";
Usage: $0 <Public ID> <AES (Secret) key> <Unique (secret) ID> [Insertion counter] [Button push counter] [Timer] [Random number]

Public ID is 0-32 (mod)hex characters (will be converted to modhex).  By 
default, yubikeys will have a 12 character modhex public id.
AES key is 32 hex characters (=128 bit key)
Insertion counter and button push counter will be set to 0 if left blank.
They may also be given as ranges, e.g. 1..5
Timer and Random number will be randomly chosen if left blank
USAGE
}

sub verifyRange($$$)
{
    my ( $value, $min, $max ) = @_;
    unless ( defined $value )
    {
	$value = $min;
    }
    elsif ( $value < $min )
    {
	$value = $min;
    }
    elsif ( $value > $max )
    {
	$value = $max;
    }

    return $value;
}

sub toModhex($$)
{
    my ( $value, $maxChars ) = @_;
    if ( length($value) > $maxChars ) 
    {
	$value = substr( $value, 0 , $maxChars );
    }

    if ( $value =~ m/^[cbdefghijklnrtuv]*$/ )
    {
	# Do nothing, is already in modhex
    }
    elsif ( $value =~ m/^[0123456789abcdef]+$/ )
    {
	$value =~ y/0123456789abcdef/cbdefghijklnrtuv/;
    }
    else
    {
	$value = "";
    }
    return $value
}

sub toBinary($$)
{
    my ( $value, $numChars ) = @_;
    my $result;
    if ( length($value) > $numChars ) 
    {
	$value = substr( $value, 0 , $numChars );
    }

    if ( $value =~ m/^[0123456789abcdef]+$/ )
    {
	# Do nothing, is already in hex
    }
    elsif ( $value =~ m/^[cbdefghijklnrtuv]*$/ )
    {
	$value =~ y/cbdefghijklnrtuv/0123456789abcdef/;
    }
    else
    {
	$value = "";
    }
    $result = pack( "H*", $value );
    return $result;
}

sub validateArgs(@)
{
    my ( $publicId,
	 $aesKey,
	 $uniqueId,
	 $insertionCounter,
	 $buttonCounter,
	 $timer,
	 $random ) = @_;
    my ( $insertionCounterMin, $insertionCounterMax, 
	 $buttonCounterMin, $buttonCounterMax );

    $publicId         = toModhex( $publicId, 32 );

    $aesKey           = toBinary( $aesKey, 32 );

    if ( $insertionCounter =~ /^([0-9]+)(..([0-9]+))?$/ )
    {
	$insertionCounterMin = verifyRange( $1, 0, 65535 );
	$insertionCounterMax = $insertionCounterMin;
	$insertionCounterMax = verifyRange( $3, 0, 65535 ) if ( $3 );
    }
    else
    {
	$insertionCounterMin = $insertionCounterMax = 0;
    }

    #$buttonCounter    = verifyRange( $buttonCounter, 0, 255 );
    if ( $buttonCounter =~ /^([0-9]+)(..([0-9]+))?$/ )
    {
	$buttonCounterMin = verifyRange( $1, 0, 255 );
	$buttonCounterMax = $buttonCounterMin;
	$buttonCounterMax = verifyRange( $3, 0, 255 ) if ( $3 );
    }
    else
    {
	$buttonCounterMin = $buttonCounterMax = 0;
    }

    $timer            = int rand(16777216) unless( defined $timer );
    $timer            = verifyRange( $timer, 0, 16777215 );

    $random           = int rand(65536) unless( defined $random );
    $random           = verifyRange( $random, 0, 65535 );

    return ( $publicId,$aesKey,$uniqueId,$insertionCounterMin, 
	     $insertionCounterMax,$buttonCounterMin,$buttonCounterMax,$timer,
	     $random);
}

sub doEncodeYubikey($$$$$$$)
{
    my ( $publicId,
	 $aesKey,
	 $uniqueId,
	 $insertionCounter,
	 $buttonCounter,
	 $timer,
	 $random ) = @_;
    # print "publicId=$publicId, aesKey=$aesKey, uniqueId=$uniqueId, " .
    # 	"insertionCounter=$insertionCounter, buttonCounter=$buttonCounter, " .
    # 	"timer=$timer, random=$random\n";
    my $binary = pack( "n3SSCCS", $uniqueId / 65536 / 65536, 
		       $uniqueId / 65536, 
		       $uniqueId % 65536, 
		       $insertionCounter, 
		       $timer % 65535, 
		       $timer / 65536, 
		       $buttonCounter,
		       $random );
    my $crc = yubikey_crc( $binary );
    $binary .= pack( "S", $crc );
    my $binhex = unpack( "H*", $binary );
    # print "binhex=$binhex\n";
    my $cipher = Crypt::Rijndael->new( $aesKey );
    my $cipherText = $cipher->encrypt( $binary );
    my $cipherHex = unpack( "H*", $cipherText );
    # print "ciperText=$cipherHex\n";
    my $output=$publicId . toModhex( $cipherHex, 32 );
    print "$output\n";
}

# Adopted from Auth::Yubikey_Decrypter, version 0.05, by Phil Massyn
# Available in CPAN
# Modified as per Yubisim, version 0.3, by Alex Jensen
# http://code.google.com/p/yubisim/
sub yubikey_crc
{
    my $buffer = $_[0];
    my $m_crc=0x5af0;
    my $j;
    for(my $bpos=0; $bpos<14; $bpos++)
    {
	$m_crc ^= ord(substr($buffer,$bpos,1)) & 0xff;
	for (my $i=0; $i<8; $i++)
	{
	    $j=$m_crc & 1;
	    $m_crc >>= 1;
	    if ($j)
	    {
		$m_crc ^= 0x8408;
	    }
	}
    }
    return $m_crc;
}

sub main()
{
    if ( @ARGV < 3 || @ARGV > 7 )
    {
	usage;
	exit 1;
    }
    

    my ( $publicId, $aesKey, $uniqueId, $insertionCounterMin, 
	 $insertionCounterMax, $buttonCounterMin, $buttonCounterMax,
	 $timer, $random ) =
	validateArgs( @ARGV );
    if ( $confirmArgs )
    {
	print "publicId=$publicId, " . 
	    "aesKey=0x" . unpack("H*",$aesKey) . ", " . 
	    "uniqueId=$uniqueId, " .
	    "insertionCounterMin=$insertionCounterMin, " . 
	    "insertionCounterMax=$insertionCounterMax, " .
	    "buttonCounterMin=$buttonCounterMin, " .
	    "buttonCounterMax=$buttonCounterMax, " .
	    "timer=$timer, random=$random\n";
    }

    my @insertionList;
    if ( $insertionCounterMin == $insertionCounterMax )
    {
	@insertionList = ( $insertionCounterMin );
    }
    elsif ( $insertionCounterMin < $insertionCounterMax )
    {
	@insertionList = ( $insertionCounterMin..$insertionCounterMax );
    }
    else
    {
	@insertionList = ( $insertionCounterMin..65535, 
			   0..$insertionCounterMax );
    }

    my @buttonList;
    if ( $buttonCounterMin == $buttonCounterMax )
    {
	@buttonList = ( $buttonCounterMin );
    }
    elsif ( $buttonCounterMin < $buttonCounterMax )
    {
	@buttonList = ( $buttonCounterMin..$buttonCounterMax );
    }
    else
    {
	@buttonList = ( $buttonCounterMin..255, 0..$buttonCounterMax );
    }

    for my $insertionCounter ( @insertionList )
    {
	for my $buttonCounter ( @buttonList )
	{
	    doEncodeYubikey( $publicId, $aesKey, $uniqueId, $insertionCounter,
			     $buttonCounter, $timer, $random );
	}
    }
}

main;
