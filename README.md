# NAME

Crypt::OpenSSL::SignCSR - Sign a Certificate Signing Request in XS.

# SYNOPSIS

```perl
use Crypt::OpenSSL::SignCSR;

my $signer = Crypt::OpenSSL::SignCSR->new(
                              $private_key_pem
                              {   # OPTIONAL
                                  days    => $days,   # Number of days for the certificate
                                  digest  => $digest, # Signature digest default (SHA256)
                                  format  => $format, # Output format "text" or "pem" (default)
                              });
my $cert   = $signer->sign(
                              $request, # CRS in PEM format
                          );

my $ret = $signer->set_days(3650);
my $ret = $signer->set_format("text");
my $ret = $signer->set_days("SHA512");

$cert   = $signer->sign( $request ); # CRS in PEM format
```

# DESCRIPTION

Allows a Certificate Signing Request (CSR) to be signed to create a
X509 PEM encoded Certificate.

# METHODS

## sign($csr)

Sign the provided CSR in PEM format.

Returns a signed certificate file in the specified format.

Arguments:

```
* $csr - a PEM format Certificate signing request.  You can create one with
Crypt::OpenSSL::PKCS10 or any other product capable of creating a signing request.
```

## set\_digest($digest)

Set the digest that should be used for signing the certificate.

Any openssl supported digest can be specified.  If the value provided is not
a valid it will set the openssl default.

Returns true (1) if successful and false (0) for a failure.

Arguments:

```
* $digest - the specified openssl supported digest (ex SHA1, SHA256, SHA384, SHA512)
```

## get\_digest()

Get the digest that is currently set.

Returns a string

## set\_format($format)

Set the format that should be used to output the the certificate.

Supported formats are "text" and "pem" (default).

Returns true (1) if successful and false (0) for a failure.

Arguments:

```
* $format - the specified output format ("pem", "text")
```

## get\_format()

Get the output format that is currently set.

Returns a string

## set\_days($days)

Set the number of days that the Certificate will be valid.  The days can
be set via the constructor or modified via set\_days()

Returns true (1) if successful and false (0) for a failure.

Arguments:

```
* $days - number of days that the certificate will be valid.
```

## get\_days()

Get the number of days that is currently set.

Returns a number

# EXPORT

None by default.

# SEE ALSO

Crypt::OpenSSL::PKCS10 allows you to generate a Certificate Signing Request (CSR)

# AUTHOR

Timothy Legge, <timlegge@cpan.org>

# COPYRIGHT

Copyright (C) 2023 by Timothy Legge
Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.

I did not write any OpenSSL related code I simply copied and pasted
the work of the OpenSSL project's openssl code until I arrived at a XS
based module that could create a certificate from a Certificate Signing Request.

&#x3d; head LICENSE

Licensed under the Apache License 2.0 (the "License").  You may not use
this file except in compliance with the License.  You can obtain a copy
in the file LICENSE in the source distribution or at
https://www.openssl.org/source/license.html
