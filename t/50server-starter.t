use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

plan skip_all => 'start_server not found'
    unless prog_exists('start_server');

my $tempdir = tempdir(CLEANUP => 1);

subtest "master-mode" => sub {
    my $server = spawn_vhttp({
        opts => [ qw(--mode=master) ],
        conf => << "EOT",
pid-file: $tempdir/vhttp.pid
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    });

    subtest 'before-HUP' => sub {
        is read_file("$tempdir/vhttp.pid"), "$server->{pid}\n", "pid";
        fetch_test($server->{port}, $server->{tls_port});
    };
    kill 'HUP', $server->{pid};
    sleep 1;
    subtest 'after-HUP' => sub {
        fetch_test($server->{port}, $server->{tls_port});
        is read_file("$tempdir/vhttp.pid"), "$server->{pid}\n", "pid unchanged";
    };

    undef $server;

    ok ! stat("$tempdir/vhttp.pid"), "pid-file is unlinked";
};

subtest "daemon-mode" => sub {
    my $server = spawn_vhttp({
        opts => [ qw(--mode=daemon) ],
        conf => << "EOT",
pid-file: $tempdir/vhttp.pid
error-log: /dev/stderr # $tempdir/vhttp.error
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    });
    my ($port, $tls_port) = map { $server->{$_} } qw(port tls_port);

    sleep 1;
    undef $server; # should have performed a double-fork by now

    my $pid = read_file("$tempdir/vhttp.pid");
    chomp $pid;

    subtest 'before-HUP' => sub {
        fetch_test($port, $tls_port);
    };
    kill 'HUP', $pid;
    sleep 1;
    subtest 'after-HUP' => sub {
        fetch_test($port, $tls_port);
        is read_file("$tempdir/vhttp.pid"), "$pid\n", "pid unchanged";
    };

    kill 'TERM', $pid;
    sleep 1;
    ok ! stat("$tempdir/vhttp.pid"), "pid-file is unlinked";
};

done_testing;

sub fetch_test {
    my ($port, $tls_port) = @_;

    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    my $curl = "curl --insecure";
    $curl .= " --http1.1"
        if curl_supports_http2();

    my $doit = sub {
        my ($proto, $port) = @_;
        my $content = `$curl --silent --show-error $proto://127.0.0.1:$port/`;
        is md5_hex($content), md5_file(DOC_ROOT . "/index.txt"), $proto;
    };
    $doit->("http", $port);
    $doit->("https", $tls_port);
}

sub read_file {
    my $fn = shift;
    open my $fh, '<', $fn
        or die "failed to open file:$fn:$!";
    join '', <$fh>;
}
