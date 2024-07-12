define FATPACK_SHEBANG
#! /bin/sh
exec $${vhttp_PERL:-perl} -x $$0 "$$@"
#! perl
endef
export FATPACK_SHEBANG

GEN_RAW_TRACER_TMPFILE := $(shell mktemp -t gen_raw_tracer.XXXXXXXX)

all: tokens lib/handler/mruby/embedded.c.h lib/http2/hpack_huffman_table.h lib/handler/file/templates.c.h clang-format-all share/vhttp/start_server share/vhttp/fastcgi-cgi share/vhttp/ca-bundle.crt src/vhttplog/generated_raw_tracer.cc

tokens:
	misc/tokens.pl

lib/handler/mruby/embedded.c.h: misc/embed_mruby_code.pl \
                                lib/handler/mruby/embedded/core.rb \
                                lib/handler/mruby/embedded/sender.rb \
                                lib/handler/mruby/embedded/middleware.rb \
                                lib/handler/mruby/embedded/http_request.rb \
                                lib/handler/mruby/embedded/redis.rb \
                                lib/handler/mruby/embedded/channel.rb
	misc/embed_mruby_code.pl $^ > $@
	clang-format -i $@

lib/http2/hpack_huffman_table.h: misc/mkhufftbl.py
	python misc/mkhufftbl.py > $@

lib/handler/file/templates.c.h: misc/picotemplate-conf.pl lib/handler/file/_templates.c.h
	misc/picotemplate/picotemplate.pl --conf misc/picotemplate-conf.pl lib/handler/file/_templates.c.h || exit 1
	clang-format -i $@

vhttp_PROBES_D=vhttp-probes.d
QUICLY_PROBES_D=deps/quicly/quicly-probes.d

src/vhttplog/generated_raw_tracer.cc: FORCE
	src/vhttplog/misc/gen_raw_tracer.py $(GEN_RAW_TRACER_TMPFILE) $(QUICLY_PROBES_D) $(vhttp_PROBES_D)
	rsync --checksum $(GEN_RAW_TRACER_TMPFILE) $@

clang-format-all:
	misc/clang-format-all.sh

clang-format-diff:
	misc/clang-format-diff.sh

share/vhttp/start_server: FORCE
	cd misc/p5-Server-Starter; \
	fatpack-simple --shebang "$$FATPACK_SHEBANG" -o ../../$@ script/start_server

share/vhttp/fastcgi-cgi: FORCE
	cd misc/p5-net-fastcgi; \
	fatpack-simple --shebang "$$FATPACK_SHEBANG" -o ../../$@ ../fastcgi-cgi.pl

share/vhttp/ca-bundle.crt: FORCE
	cd share/vhttp; \
	../../misc/mk-ca-bundle.pl; \
	rm -f certdata.txt

FORCE:

.PHONY: tokens clang-format-all FORCE
