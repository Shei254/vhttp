use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(wait_port);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/vhttp-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $upstream = spawn_server(
    argv => [
        qw(plackup -s Starlet --max-workers 10 --access-log /dev/null --listen), "$tempdir/upstream.sock",
        ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub { !! -e "$tempdir/upstream.sock" },
);
sleep 1;

my $server = spawn_vhttp(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/vhttp/server.key
    certificate-file: examples/vhttp/server.crt
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://[unix:$tempdir/upstream.sock]/
http3-max-concurrent-streaming-requests-per-connection: 6
EOT

# send 3 requests to /suspend-body, check that all the header fields are received before the content
sub fetch3 {
    my $opts = shift;
    open my $client_fh, "-|", "$client_prog -3 100 -C 3 -t 3 $opts https://127.0.0.1:$quic_port/suspend-body 2>&1"
        or die "failed to spawn $client_prog:$!";
    local $/;
    join "", <$client_fh>;
}

my $resp_concurrent = qr!^(?:HTTP/[0-9\.]+ 200.*?\n\n){3}x{3}$!s;

like fetch3("-m POST -b 1000000 -c 10000 -i 50"), $resp_concurrent, "POST of 1MB (taking 5 seconds) is concurrent";

done_testing;
