use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => "could not find memcached"
    unless prog_exists("memcached");

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");

my $tempdir = tempdir(CLEANUP => 1);

doit("binary");
doit("ascii");

done_testing;

sub doit {
    my $memc_proto = shift;
    subtest $memc_proto => sub {
        # start memcached
        my $memc_port = empty_port();
        my $memc_user = getlogin || getpwuid($<);
        my $memc_guard = spawn_server(
            argv     => [ qw(memcached -l 127.0.0.1 -p), $memc_port, "-B", $memc_proto, "-u", $memc_user ],
            is_ready => sub {
                check_port($memc_port);
            },
        );
        # the test
        my $spawn_and_connect = sub {
            my ($opts, $expected) = @_;
            my $server = spawn_vhttp({conf => << "EOT", max_ssl_version => "TLSv1.2", disable_quic => 1});
ssl-session-resumption:
  mode: cache
  cache-store: memcached
  memcached:
    host: 127.0.0.1
    port: $memc_port
    protocol: $memc_proto
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
            sleep 1; # wait for vhttp to connect to memcached
            my $lines = run_openssl_client({ host => "127.0.0.1", port => $server->{tls_port}, opts => "-no_ticket $opts" });
            $lines =~ m{---\n(New|Reused),}s
                or die "failed to parse the output of s_client:{{{$lines}}}";
            is $1, $expected;
            sleep 1; # wait for vhttp to commit to memcached
        };
        $spawn_and_connect->("-sess_out $tempdir/session", "New");
        $spawn_and_connect->("-sess_in $tempdir/session", "Reused");
    };
}
