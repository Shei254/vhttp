use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'cgi file' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn vhttp
    my $server = spawn_vhttp(<< "EOT");
file.custom-handler:
  extension: .cgi
  fastcgi.spawn: "exec \$vhttp_ROOT/share/vhttp/fastcgi-cgi"
hosts:
  default:
    paths:
      /robots.txt:
        file.file: @{[DOC_ROOT]}/hello.cgi
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/robots.txt?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

subtest 'cgi file with no extension' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn vhttp
    my $server = spawn_vhttp(<< "EOT");
file.custom-handler:
  extension: default
  fastcgi.spawn: "exec \$vhttp_ROOT/share/vhttp/fastcgi-cgi"
hosts:
  default:
    paths:
      /robots.txt:
        file.file: @{[DOC_ROOT]}/noextcgi
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/robots.txt?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

subtest 'directory containing cgi files' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn vhttp
    my $server = spawn_vhttp(<< "EOT");
file.custom-handler:
  extension: ["default", ".cgi"]
  fastcgi.spawn: "exec \$vhttp_ROOT/share/vhttp/fastcgi-cgi"
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/hello.cgi?name=Tobor`;
        is $resp, "Hello Tobor";
    });

    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/noextcgi?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

subtest 'treat .html as cgi by resetting mimetypes' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn vhttp
    my $server = spawn_vhttp(<< "EOT");
file.mime.settypes: {}
file.custom-handler:
  extension: ["default"]
  fastcgi.spawn: "exec \$vhttp_ROOT/share/vhttp/fastcgi-cgi"
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/cgi.html?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

subtest 'SCRIPT_NAME and PATH_INFO for fastcgi' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn vhttp
    my $server = spawn_vhttp(<< "EOT");
file.index: ['printenv.cgi']
file.custom-handler:
  extension: .cgi
  fastcgi.spawn: "exec \$vhttp_ROOT/share/vhttp/fastcgi-cgi"
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
      /foo:
        file.dir: @{[DOC_ROOT]}
EOT
    my $doit = sub {
        my ($path, $expected) = @_;
        subtest $path => sub {
            run_with_curl($server, sub {
                my ($proto, $port, $cmd) = @_;
                my $resp = `$cmd --silent $proto://127.0.0.1:$port$path`;
                my $env = +{ map { split(':', $_, 2) } split(/\n/, $resp) };
                for my $key (sort keys %$expected) {
                    is $env->{$key}, $expected->{$key}, $key;
                }
            });
        };
    };

    $doit->('/printenv.cgi',
        +{ SCRIPT_NAME => '/printenv.cgi', PATH_INFO => undef });
    $doit->('/printenv.cgi/path/info',
        +{ SCRIPT_NAME => '/printenv.cgi', PATH_INFO => '/path/info' });
    $doit->('/foo/printenv.cgi/path/info',
        +{ SCRIPT_NAME => '/foo/printenv.cgi', PATH_INFO => '/path/info' });
    $doit->('/',
        +{ SCRIPT_NAME => '/printenv.cgi', PATH_INFO => undef });
    $doit->('/foo/',
        +{ SCRIPT_NAME => '/foo/printenv.cgi', PATH_INFO => undef });

};

subtest 'pathconf' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn vhttp
    my $server = spawn_vhttp(<< "EOT");
file.index: ['printenv.cgi']
file.custom-handler:
  extension: .cgi
  fastcgi.spawn: "exec \$vhttp_ROOT/share/vhttp/fastcgi-cgi"
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
        header.set: "path: 3"
    header.set: "host: 2"
header.set: "global: 1"
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/hello.cgi?name=vhttp`;
        like $resp, qr{\nglobal: 1\r?\nhost: 2\r?\npath: 3\r?\n.*\r?\nHello vhttp$}s;
    });
};

done_testing;
