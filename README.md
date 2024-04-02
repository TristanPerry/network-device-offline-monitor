# network-device-offline-monitor
A simple way of getting notified by email if one or more local network devices go offline for any reason.

This will scan any IP ranges specified in config.ini (see `IpRangesToScan`) and checks that any IPs mentioned in `RequiredIps` are online. If they aren't, it will send an email to the specified notification email.

This script is designed for Linux since it uses nmap, however it should run on a Windows OS as long as nmap is installed (https://nmap.org/book/inst-windows.html) and available on the `PATH`. I haven't tested this though.

## Config

The `config.ini` file is fairly basic: update the notification name and email address as needed. Then there's just two IP address items: the IP ranges to scan (`IpRangesToScan`), and which IP(s) are should be required as online (`RequiredIps`).

`IpRangesToScan` is basically the list of IP subnets that you want to scan. If you have a single router and all your devices have IP addresses in the same range (e.g. `192.168.1.30` and `192.168.1.202`) then you might just need to enter a single value here such as `192.168.1.0/24`.

However if you have multiple Wi-Fi points (for example you run a mesh Wi-FI set-up), you might need to enter multiple values here. I have four Eero Pro 6 points and my devices connect over `192.168.4.*`, `192.168.6.*` and `192.168.7.*` so that's why I have entered three IP ranges here.

## How To Run

This uses the Mailersend API to send emails (although naturally you can use your own provider or approach by modifying `send_email_notification()`).

The Mailersend API key can only be specified by an environment variable: `MAILERSEND_API_KEY`

So you can run this script by modifying `config.ini` as required, and then running something like:

> MAILERSEND_API_KEY='changeme' python3 main.py

You can also change the logging level by adding a `--loglevel` param, for example by running:

> MAILERSEND_API_KEY='changeme' python3 main.py --loglevel debug
