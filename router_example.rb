require_relative "lib/ruby-router/ruby-router"

  RubyRouter::Router.new(
  "eth0",
  "wlan0",
  "192.168.10.121",
  "hci0",
  [
    "2C:CF:67:83:EA:E4",
  ]
  ).run
