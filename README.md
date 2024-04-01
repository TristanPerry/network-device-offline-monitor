# network-device-offline-monitor
A simple way of getting notified by email if one or more local network devices go offline for any reason.

This will scan any IP ranges specified in config.ini (see `IpRangesToScan`) and checks that any IPs mentioned in `RequiredIps` are online. If they aren't, it will send an email to the specified notification email.

This script is designed for Linux since it uses nmap, however it might be possible to run it on a Windows OS as long as nmap is installed (https://nmap.org/book/inst-windows.html) and available on the `PATH`. I haven't tested this though.

## How To Run

This uses the Mailersend API to send emails (although naturally you can use your own provider or approach by modifying `send_email_notification()`).

The Mailersend API key can only be specified by an environment variable: `MAILERSEND_API_KEY`

So you can run this script by modifying `config.ini` as required, and then running something like:

> MAILERSEND_API_KEY='changeme' python3 main.py

You can also change the logging level by adding a `--loglevel` param, for example by running:

> MAILERSEND_API_KEY='changeme' python3 main.py --loglevel debug
