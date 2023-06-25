# ABSTRACT OpenSSL Self Sign a Certificate Signing Request in XS.
package Crypt::OpenSSL::SignCSR;

use 5.014;
use strict;
use warnings;

require Exporter;

our $VERSION  = "0.04";

our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw(

) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

require XSLoader;
XSLoader::load('Crypt::OpenSSL::SignCSR', $VERSION);

1;
__END__

=head1 NAME

Crypt::OpenSSL::SignCSR - Sign a Certificate Signing Request in XS.

=head1 SYNOPSIS

  use Crypt::OpenSSL::SignCSR;

  my $signer = Crypt::OpenSSL::SignCSR->new($private_key_pem);
  my $cert   = $signer->sign(
                                $request, # CRS in PEM format
                                $days,      # number of days for the certificate
                                $digest     # Signature digest default (SHAi256)
                                $text,      # Boolean (text format output (1) PEM (0)
                                ''          # FIXME
                            );

=head1 DESCRIPTION

Allows a Certificate Signing Request (CSR) to be signed to create a
X509 PEM encoded Certificate.

WARNING: Early release.

I am almost certainly going to change the way the module is initialized.
The Key being kept in memory is probably not the best approach.  It will be
moved to the sign sub-routine.

=head1 EXPORT

None by default.

=head1 SEE ALSO

Crypt::OpenSSL::PKCS10 allows you to generate a Certificate Signing Request (CSR)

=head1 AUTHOR

Timothy Legge, E<lt>timlegge@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (C) 2023 by Timothy Legge
Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.

I did not write any OpenSSL related code I simply copied and pasted
the work of the OpenSSL project's openssl code until I arrived at a XS
based module that could create a certificate from a Certificate Signing Request.

= head LICENSE

Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html

=cut
