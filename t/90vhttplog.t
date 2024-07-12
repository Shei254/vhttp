#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# vhttpLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use Test::More;
use JSON;
use t::Util;

get_exclusive_lock(); # take exclusive lock before sudo closes LOCKFD
run_as_root();

my $vhttplog_prog = bindir() . "/vhttplog";
my $client_prog = bindir() . "/vhttp-httpclient";

unless ($ENV{DTRACE_TESTS})  {
  plan skip_all => "$vhttplog_prog not found"
      unless -e $vhttplog_prog;

  plan skip_all => "$client_prog not found"
      unless -e $client_prog;

  plan skip_all => 'dtrace support is off'
      unless server_features()->{dtrace};
}

my $server = spawn_vhttp({
    opts => [qw(--mode=worker)],
    user => scalar(getpwuid($ENV{SUDO_UID})),
    conf => << "EOT",
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
});

subtest "vhttplog", sub {
  my $tracer = vhttplogTracer->new({
    pid => $server->{pid},
    args => [],
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ m{"h3s-destroy"}) {}

  if ($ENV{vhttpLOG_DEBUG}) {
    diag "vhttplog output:\n", $trace;
  }

  my @events = map { decode_json($_) } split /\n/, $trace;
  is scalar(grep { $_->{type} && $_->{tid} && $_->{seq} } @events), scalar(@events), "each event has type, tid and seq";

  my($h3s_accept) = grep { $_->{type} eq "h3s-accept" } @events;
  ok is_uuidv4($h3s_accept->{"conn-uuid"}), "h3s-accept has a UUIDv4 field `conn-uuid`"
};

subtest "vhttplog -t", sub {
  my $tracer = vhttplogTracer->new({
    pid => $server->{pid},
    args => [
      "-t", "vhttp:send_response_header",
      "-t", "vhttp:receive_request_header",
      "-t", "vhttp:h3s_destroy",
    ],
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ m{"h3s-destroy"}) {}

  if ($ENV{vhttpLOG_DEBUG}) {
    diag "vhttplog output:\n", $trace;
  }

  my %group_by;
  foreach my $event (map { decode_json($_) } split /\n/, $trace) {
    $group_by{$event->{"type"}}++;
  }

  is_deeply [sort keys %group_by], [sort qw(h3s-destroy send-response-header receive-request-header)];
};

subtest "vhttplog -H", sub {
  my $tracer = vhttplogTracer->new({
    pid => $server->{pid},
    args => ["-H"],
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ m{\bRxProtocol\b}) {}

  if ($ENV{vhttpLOG_DEBUG}) {
    diag "vhttplog output:\n", $trace;
  }

  like $trace, qr{\bRxProtocol\s+HTTP/3.0\b};
  like $trace, qr{\bTxStatus\s+200\b};
};

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

done_testing();

sub is_uuidv4 {
  my($s) = @_;

  # sited from https://stackoverflow.com/a/19989922/805246
  $s =~ /\A[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\z/i;
}
