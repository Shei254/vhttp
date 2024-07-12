use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => "vhttp is not built with libaegis"
    unless server_features()->{libaegis};

my $port = empty_port();

my $server = spawn_vhttp_raw(<< "EOT", [ $port ]);
listen:
  port: $port
  ssl:
    key-file: examples/vhttp/server.key
    certificate-file: examples/vhttp/server.crt
    cipher-suite-tls1.3: [ "TLS_AEGIS_128L_SHA256" ]
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

sleep 1;

undef $server;

ok "just made sure that the server spawns";

done_testing;
