require_relative "lib/ruby-router/ruby-router"

  RubyRouter::Router.new(
  "eth0",
  "wlan0",
  "172.20.0.1",
  "hci0",
  [
    "2C:CF:67:83:EA:E4",
  ]
).run
