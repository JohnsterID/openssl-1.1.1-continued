#! /usr/bin/env perl
# Copyright 2026 JohnsterID (1.1.1zi-carry). Not part of OpenSSL's own tests.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_internal_carry");

simple_test("test_internal_carry", "carry_internal_test");
