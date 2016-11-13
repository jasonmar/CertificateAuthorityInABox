## Description

This provides an example implementation of a certificate authority which can be used to generate client certificates.

## Motivation

When using AWS you may want to run a web service with TLS.
Having your very own CA to generate wildcard certificates which work on EC2 instances and localhost can make this easy.
Trust your root certificate to prevent your browser and other clients from throwing path validation errors.

## Features

  * Generates Root CA KeyPair and Certificate
  * Generates Intermediate CA KeyPair and Certificate
  * Generates Client CA KeyPair and Certificate
  * Client Certificate is a wildcard for any AWS EC2 Instance as well as for localhost and 127.0.0.1
  * Client Certificate includes multiple extensions

## Installation

You must have sbt and the jdk installed.
It helps for the sbt bin directory to be included in your PATH environment variable.
Also, the JAVA_HOME environment variable must be set to the root directory of your JDK in order for sbt to work.
After using git to clone the repository, starting the application is easy.
In your console execute "sbt run" and all certs will be generated in the working directory.

## License

This project uses the Apache 2.0 license. Read LICENSE file.

## Authors and Copyright

Copyright (C) 2016 Jason Mar
