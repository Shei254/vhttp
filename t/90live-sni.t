use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

our $CA_CERT = "misc/test-ca/root/ca.crt";

# using wget since curl of OS X 10.9.5 returns invalid certificate chain error with the test
plan skip_all => 'wget not found'
    unless prog_exists('wget');

plan skip_all => 'only wget >= 1.14 supports SNI'
    unless `wget --version` =~ /^GNU Wget 1\.([0-9]+)/ && $1 >= 14;

plan skip_all => "skipping live tests (setenv LIVE_TESTS=1 to run them)"
    unless $ENV{LIVE_TESTS};

subtest "basic" => sub {
    my $server = spawn_vhttp(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "localhost.examp1e.net:$tls_port":
    paths:
      /:
        file.dir: examples/doc_root
  "alternate.localhost.examp1e.net:$tls_port":
    listen:
      port: $tls_port
      ssl:
        key-file: examples/vhttp/alternate.key
        certificate-file: examples/vhttp/alternate.crt
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT
    });

    do_test(
        "localhost.examp1e.net:$server->{tls_port}",
        md5_file("examples/doc_root/index.html"),
    );

    do_test(
        "alternate.localhost.examp1e.net:$server->{tls_port}",
        md5_file("examples/doc_root.alternate/index.txt"),
    );
};

subtest "wildcard" => sub {
    my $server = spawn_vhttp(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "localhost.examp1e.net:$tls_port":
    paths:
      /:
        file.dir: examples/doc_root
  "*.localhost.examp1e.net:$tls_port":
    listen:
      port: $tls_port
      ssl:
        key-file: examples/vhttp/alternate.key
        certificate-file: examples/vhttp/alternate.crt
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT
    });

    do_test(
        "localhost.examp1e.net:$server->{tls_port}",
        md5_file("examples/doc_root/index.html"),
    );

    do_test(
        "alternate.localhost.examp1e.net:$server->{tls_port}",
        md5_file("examples/doc_root.alternate/index.txt"),
    );
};


done_testing();

sub do_test {
    my ($authority, $md5_expected) = @_;
    my $content = `wget -nv --ca-certificate=$CA_CERT -O - https://$authority/`;
    is $?, 0, "wget returns success";
    is md5_hex($content), $md5_expected, "content is as expected";
}
