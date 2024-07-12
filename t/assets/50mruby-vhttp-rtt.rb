Proc.new do |env|
  rtt = nil
  unless env["vhttp.get_rtt"].nil?
    rtt = env["vhttp.get_rtt"].call()
    while rtt.nil? do
      sleep(0.1)
      rtt = env["vhttp.get_rtt"].call()
    end
  end
  if rtt.nil?
    rtt = 'N/A'
  end
  [200, {}, ["RTT = ", rtt]]
end
