# curlmypoison
This program targets services such as icanhazip.com to show why plain-text
HTTP is such as bad idea. Users do something like "curl http://icanhazip.com"
and receive back their public IP address. This program hijacks the TCP session
and returns a bogus HTTP response hopefully before the actual service responds.
Think of all the plain-text services people rely on, for instance DNS and NTP.

```
sudo ./curlmypoison -p -i eth1 -o eth1
```

is equivalent to

```
sudo ./curlmypoison -p -i eth1 -o eth1 -f "tcp and dst port 80"
```

you can also target specific (destination) hosts

```
sudo ./curlmypoison -p -i eth1 -o eth1 -f "ip and host 93.184.216.34 and tcp and dst port 80"
```

CAUTION! Make sure your filter captures ONLY the target's traffic (as shown
above) otherwise curlmypoison will fall into a loop where it captures its own
TCP+PA injections, assumes they are the victim's requests and responds to them
with new injections :)
