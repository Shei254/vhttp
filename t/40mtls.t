use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tls_port = empty_port();
my $good_client_key_cert = '--key t/assets/test_client.key --cert t/assets/test_client.crt';
my $wrong_client_key_cert = '--key examples/vhttp/server.key --cert examples/vhttp/server.crt';
my $TLS_RE_OK = qr{hello};

subtest "tls1.2" => sub {
    my $server = spawn_vhttp_server("tlsv1.2");
    run_tests('');
};

subtest "tls1.3" => sub {
    plan skip_all => 'curl does not support TLS 1.3'
        unless curl_support_tls13();
    my $server = spawn_vhttp_server("tlsv1.3");
    run_tests('--tlsv1.3');
};

subtest "tls1.3 with picotls-cli", sub {
    # regiression test case for https://github.com/vhttp/vhttp/pull/2679
    # use picotls-cli because it calls write(2) for the while request at once,
    # whereas openssl calls write(2) for each TLS record.
    my $server = spawn_vhttp_server("tlsv1.3");
    like run_picotls_client({ port => $tls_port, opts => "-k t/assets/test_client.key -C t/assets/test_client.crt" }), $TLS_RE_OK, "correct client cert";
    like(
        run_picotls_client({ port => $tls_port }),
        qr/^ptls_receive:372$/m,
        "no client cert -> certificate_required alert from peer (116+256)",
    );
    like(
        run_picotls_client({ port => $tls_port, opts => "-k examples/vhttp/server.key -C examples/vhttp/server.crt" }),
        qr/^ptls_receive:304$/m,
        "wrong client cert -> unknown_ca alert from peer (48+256)",
    );
};

done_testing;

sub run_tests {
    my $opts = shift;
    like run_tls_client("$opts $good_client_key_cert"), $TLS_RE_OK, "correct client cert";
    unlike run_tls_client($opts), $TLS_RE_OK, "no client cert";
    unlike run_tls_client("$opts $wrong_client_key_cert"), $TLS_RE_OK, "wrong client cert";
}

sub run_tls_client {
    my $opts = shift;
    my $resp = `curl $opts --cacert misc/test-ca/root/ca.crt --silent --show-error https://localhost.examp1e.net:$tls_port`;
    return $resp;
}

sub spawn_vhttp_server {
    my $tls_max = shift;
    die "invalid arg:$tls_max" unless $tls_max =~ /^tlsv/;
    spawn_vhttp_raw(<<"EOT", [ $tls_port ]);
hosts:
  "default":
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
listen:
  port: $tls_port
  ssl: &ssl
    max-version: $tls_max
    key-file: examples/vhttp/server.key
    certificate-file: examples/vhttp/server.crt
    client-ca-file: misc/test-ca/intermediate/ca.crt
EOT
}

sub curl_support_tls13 {
    # Unavailability of TLS 1.3 support can be detected only after curl connects to the server. Therefore, we setup a dummy server,
    # run curl, accept a connection, then see what happens
    my $listen = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1:0",
        Proto     => "tcp",
        Listen    => 5,
    ) or die "failed to listen to random port:$!";
    open my $fh, "-|", "curl --tlsv1.3 --silent --show-error https://127.0.0.1:@{[$listen->sockport]}/ 2>&1"
        or die "failed to launch curl:$!";
    $listen->accept;
    sleep 0.5;
    close $listen;
    close $fh;
    $? >> 8 != 4; # exit status 4 indicates missing feature
}
