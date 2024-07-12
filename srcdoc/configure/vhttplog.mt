? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Using vhttplog for Tracing")->(sub {

<p>vhttplog is an experimental <a href="https://www.kernel.org/doc/html/latest/bpf/index.html">BPF</a> (<a href="https://www.kernel.org/doc/Documentation/networking/filter.txt">kernel doc</a>) backed tracing tool for the <a href="https://github.com/vhttp/vhttp">vhttp</a> server.
It can be used for tracing quicly and vhttp USDT probes.</p>

<p><em>Since vhttplog is an experimental program, its command-line interface might change without notice.</em></p>

<h2 id="installing-from-source">Installing from Source</h2>

<p>See <a href="#requirements">requirements</a> for build prerequisites.</p>
<p>If dependencies are satisfied, vhttplog is built automatically. It is possible to manually turn on / off the build of vhttplog by using the <code>-DWITH_vhttpLOG</code> option. This option takes either <code>ON</code>> or <code>OFF</code> as the argument.</p>
<p>If you have <code>BCC</code> installed to a non-standard path, use <code>pkg-config</code> for <code>cmake</code>.

<?= $ctx->{code}->(<<'EOT')
$ PKG_CONFIG_PATH=/path/to/bcc/lib/pkgconfig cmake [options]
EOT
?>

<h2 id="requirements">Requirements</h2>

<h3>For building vhttplog</h3>
<ul>
<li>C++11 compiler</li>
<li>CMake for generating the build files</li>
<li>pkg-config for detecting dependencies</li>
<li>Python 3 for the code generator</li>
<li><a href="https://iovisor.github.io/bcc/">BCC</a> (BPF compiler collection, a.k.a. bpfcc; &gt;= 0.11.0) <a href="https://github.com/iovisor/bcc/blob/master/INSTALL.md">installed</a> on your system</li>
</ul>
<p>For Ubuntu 20.04 or later, you can install dependencies with:</p>
<?= $ctx->{code}->(<<'EOT')
$ sudo apt install clang cmake python3 libbpfcc-dev linux-headers-$(uname -r)
EOT
?>
<h3>For running vhttplog</h3>
<ul>
<li>Root privilege to execute vhttplog</li>
<li>Linux kernel (&gt;= 4.10)</li>
</ul>

<h2 id="quicstart">Quickstart</h2>
<p><code>vhttplog -H -p $vhttp_PID</code> shows <a href="https://varnish-cache.org/docs/trunk/reference/varnishlog.html">varnishlog</a>-like tracing.</p>

<?= $ctx->{code}->(<<'EOT')
$ sudo vhttplog -H -p $(pgrep -o vhttp)

11 0 RxProtocol HTTP/3.0
11 0 RxHeader   :authority torumk.com
11 0 RxHeader   :method GET
11 0 RxHeader   :path /
11 0 RxHeader   :scheme https
11 0 TxStatus   200
11 0 TxHeader   content-length 123
11 0 TxHeader   content-type text/html
... and more ...
EOT
?>

<h2 id="tracing-usdt-events">Tracing USDT events</h2>
<p>Server-side <a href="https://en.wikipedia.org/wiki/QUIC">QUIC</a> events can be traced using the <code>quic</code> subcommand.
Events are rendered in <a href="https://jsonlines.org/">JSON Lines</a> format.</p>

<?= $ctx->{code}->(<<'EOT')
$ sudo vhttplog -p $(pgrep -o vhttp)
EOT
?>

<p>Here’s an example trace.</p>

<?= $ctx->{code}->(<<'EOT')
{"time":1584380825832,"type":"accept","conn":1,"dcid":"f8aa2066e9c3b3cf"}
{"time":1584380825835,"type":"crypto-decrypt","conn":1,"pn":0,"len":1236}
{"time":1584380825832,"type":"quictrace-recv","conn":1,"pn":0}
{"time":1584380825836,"type":"crypto-handshake","conn":1,"ret":0}
... and more ...
EOT
?>

? })
