#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# TEST_DEBUG=1 for more logs
# TEST_QLOG_DIR=<dir> to save qlogs to <dir>
#   vhttplog1-qlog.json - the output of vhttplog v1
#   vhttplog2-qlog.json - the output of vhttplog v2

use strict;
use warnings FATAL => "all";
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use JSON;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use t::Util;

get_exclusive_lock(); # take exclusive lock before sudo closes LOCKFD
run_as_root();

my $vhttplog_prog = bindir() . "/vhttplog";
my $client_prog = bindir() . "/vhttp-httpclient";
my $qlog_adapter = "./deps/quicly/misc/qlog-adapter.py";

my $tempdir = tempdir(CLEANUP => 1);
my $qlog_dir = $ENV{TEST_QLOG_DIR} || $tempdir;
make_path($qlog_dir);


unless ($ENV{DTRACE_TESTS})  {
  plan skip_all => "$vhttplog_prog not found"
      unless -e $vhttplog_prog;

  plan skip_all => "$client_prog not found"
      unless -e $client_prog;
}

sub spawn_vhttp_with_quic {
  my ($vhttplog_args, $logfile) = @_;

  my $quic_port = empty_port({
      host  => "127.0.0.1",
      proto => "udp",
  });

  my $server = spawn_vhttp({
  opts => [qw(--mode=worker)],
  user => scalar(getpwuid($ENV{SUDO_UID})),
  conf => << "EOT",
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
        file.dir: t/assets/doc_root
  vhttplog:
    vhttplog: appdata
    listen:
      type: unix
      port: $tempdir/vhttplog.sock
    paths: {}
EOT
  });

  wait_port({
    port => $quic_port,
    proto => "udp",
  });

  $server->{quic_port} = $quic_port;

  return $server;
}

subtest "vhttplog to qlog", sub {
  # vhttplog and vhttplog2 can attach an vhttp process at the same time,
  # so they do to compare their outputs.
  # The raw outputs are not the same, though. qlog-converted ones must be equivalent.
  my $server = spawn_vhttp_with_quic();

  # vhttplog v2
  my $vhttplog2_output_file = "$qlog_dir/vhttplog2.json";
  system("$vhttplog_prog -u $tempdir/vhttplog.sock > $vhttplog2_output_file &");

  # vhttplog v1
  my $tracer = vhttplogTracer->new({
    pid => $server->{pid},
    args => [],
    output_dir => $qlog_dir,
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/halfdome.jpg");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";
  my $vhttplog1_output_file = $tracer->{output_file};

  diag "shutting down vhttp and vhttplog ...";
  undef $server;
  undef $tracer;
  diag "done";

  my $vhttplog1_qlog = `$qlog_adapter < $vhttplog1_output_file | tee $qlog_dir/vhttplog1-qlog.json`;
  my $vhttplog2_qlog = `$qlog_adapter < $vhttplog2_output_file | tee $qlog_dir/vhttplog2-qlog.json`;

  my $vhttplog1_qlog_obj = eval { decode_json($vhttplog1_qlog) } or diag($@, $vhttplog1_qlog);
  my $vhttplog2_qlog_obj = eval { decode_json($vhttplog2_qlog) } or diag($@, $vhttplog2_qlog);

  is_deeply $vhttplog1_qlog_obj, $vhttplog2_qlog_obj, "vhttplog v1 and v2 outputs are equivalent";
};

done_testing();
