Proc.new do |env|
  [200, {"content-type" => "text/plain; charset=utf-8"}, ["hello from vhttp_mruby\n"]]
end
