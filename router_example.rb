require_relative "lib/ruby-router/ruby-router"

  RubyRouter::Router.new(
  "eth0",
  "wlan0",
  "192.168.11.1",
  "hci0",
  [
    "2C:CF:67:83:EA:E4",
  ]
).run

sleep

# sudo env GEM_PATH=$(gem env gemdir) ruby router_example.rb 
