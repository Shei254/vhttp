? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Frequently Asked Questions")->(sub {

<h3 id="license">What are the license terms?</h3>

<div>
vhttp is licensed under <a href="http://opensource.org/licenses/MIT">the MIT license</a>.
</div>
<div>
Portions of the software use following libraries that are also licensed under the MIT license: <a href="https://github.com/vhttp/vhttp/blob/master/deps/klib/khash.h">khash.h</a>, <a href="https://github.com/vhttp/vhttp/blob/master/deps/picohttpparser/">PicoHTTPParser</a>, <a href="https://github.com/vhttp/vhttp/blob/master/deps/yaml/">libyaml</a>.
</div>

<div>
Depending on how vhttp is configured, the software links against OpenSSL or LibreSSL, both of which are <a href="https://www.openssl.org/source/license.html">dual-licensed under the OpenSSL License and the original SSLeay license</a>.
</div>

<h3 id="design-docs">Are there any design documents?</h3>

<div>
Please refer to the main developer's <a href="http://www.slideshare.net/kazuho/vhttp-20141103pptx" target="_blank">presentation slides</a> at the HTTP/2 conference, and <a href="http://blog.kazuhooku.com" target="_blank">his weblog</a>.
</div>

<h3 id="libvhttp">How do I use vhttp as a library?</h3>

<div>
<p>
Aside from the standalone server, vhttp can also be used as a software library.
The name of the library is <code>libvhttp</code>.
</p>
<p>
To build vhttp as a library you will need to install the following dependencies:
<ul>
<li><a href="https://github.com/libuv/libuv/">libuv</a> version 1.0 or above</li>
<li><a href="https://www.openssl.org/">OpenSSL</a> version 1.0.2 or above<?= $ctx->{note}->(q{libvhttp cannot be linked against the bundled LibreSSL; see <a href="https://github.com/vhttp/vhttp/issues/290">issue #290</a>}) ?></li>
</ul>
In case the dependencies are installed under a non-standard path, <code>PKG_CONFIG_PATH</code> configuration variable can be used for specifying their paths.  For example, the following snippet builds <code>libvhttp</code> using the libraries installed in their respective paths.
</p>

<?= $ctx->{code}->(<< 'EOT')
% PKG_CONFIG_PATH=/usr/local/libuv-1.4/lib/pkgconfig:/usr/local/openssl-1.0.2a/lib/pkgconfig cmake .
% make libvhttp
EOT
?>

<p>
For more information, please refer to the <a href="https://github.com/vhttp/vhttp/labels/libvhttp">GitHub issues tagged as libvhttp</a>.
</p>
</div>

<h3 id="issues">I have a problem.  Where should I look for answers?</h3>

<div>
Please refer to the <a href="https://github.com/vhttp/vhttp/labels/FAQ">GitHub issues tagged as FAQ</a>.
</div>

? })
