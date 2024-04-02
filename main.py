import configparser
import argparse
import logging
import nmap3
import os

from mailersend import emails

logger = logging.getLogger(__name__)


def to_list(string: str) -> list:
    split = string.splitlines()
    return list(filter(None, split))


def load_config_values() -> tuple[list, str, str, list]:
    config = configparser.ConfigParser()
    config.read('config.ini')

    to_scan = config['DEFAULT']['IpRangesToScan']
    notification_name = config['DEFAULT']['OfflineNotificationName']
    notification_email = config['DEFAULT']['OfflineNotificationEmail']
    required_ips = config['DEFAULT']['RequiredIps']
    logger.debug('Config loaded. (to_scan) %s, (email) %s, (ips) %s', to_scan, notification_email, required_ips)

    return to_list(to_scan), notification_name, notification_email, to_list(required_ips)


def up(nmap_result: dict) -> bool:
    # Not all nmap results have a state (e.g. if they are summary or 'debug' type dict entries)
    return 'state' in nmap_result and nmap_result['state']['state'] == 'up'


def get_active_local_ips(to_scan: list) -> list:
    """
    Performs an NMAP ARP discovery scan on the specified IP ranges to see what IPs are online within these ranges.

    :param to_scan: the IP address ranges to scan.
    :return: IP addresses that the NMAP ARP scan have determined as being up (online).
    """
    nmap = nmap3.NmapHostDiscovery()
    active_ips_in_range = []

    for host in to_scan:
        logger.info('Scanning host range %s', host)
        results = nmap.nmap_arp_discovery(host)
        logger.debug('Results for host range %s', host)
        logger.debug(results)

        up_ips = {ip: result for ip, result in results.items() if up(result)}

        up_ips_list = list(up_ips.keys())
        logger.debug('%s IPs are UP for host range %s', up_ips_list, host)
        active_ips_in_range.extend(up_ips_list)

    return active_ips_in_range


def send_email_notification(up_ips: list, error_ips: list, notification_name: str, notification_email: str) -> None:
    logger.error('IP(s) %s are offline, sending email to %s', error_ips, notification_email)
    mailer = emails.NewEmail(os.getenv('MAILERSEND_API_KEY'))

    mail_body = {}

    mail_from = {
        "name": "Offline Notifier",
        "email": notification_email,
    }

    recipients = [
        {
            "name": notification_name,
            "email": notification_email,
        }
    ]

    reply_to = [
        {
            "name": "Offline Notifier (No Reply)",
            "email": notification_email,
        }
    ]

    message = 'Warning! The following required IP addresses are offline: ' + ', '.join(error_ips) + ("\n\n "
                "The detected online IPs were: " + ', '.join(up_ips))

    mailer.set_mail_from(mail_from, mail_body)
    mailer.set_mail_to(recipients, mail_body)
    mailer.set_reply_to(reply_to, mail_body)
    mailer.set_subject("Network Device(s) Offline", mail_body)
    mailer.set_plaintext_content(message, mail_body)

    response = mailer.send(mail_body)
    logger.debug("Email response: %s", response)


def ping_potentially_offline_ips(ips_to_check: list) -> list:
    """
    The 'basic' NMAP ARP check can sometimes flag up false negatives (i.e. reporting that some IPs are offline, even
    when they are not) - so we do a further check on them here before ruling that they are 'definitely' offline.

    :param ips_to_check: IP addresses that a 'basic' ARP check thinks are offline.
    :return: a list of 'definitely' offline IPs (as best as we can check without detailed knowledge of each IP).
    """
    nmap = nmap3.NmapScanTechniques()
    definitely_offline_ips = []

    for ip in ips_to_check:
        logger.debug("Checking IP %s for see if it is 'definitely' offline", ip)

        # NmapScanTechniques includes TDP, UDP and ping scans (and others that require root access). It's hard to know
        # which scan technique is 'best' here because some IPs might run UDP services (for example) or not reply to
        # pings, but overall I think that a ping scan is better than a TDP scan (since we have UDP-heavy IPs, after all)
        ping_result = nmap.nmap_ping_scan(ip)
        logger.debug("ping_scan result for IP %s", ip)
        logger.debug(ping_result)

        if not up(ping_result):
            definitely_offline_ips.append(ip)

    logger.debug("Determined that IPs %s were offline based on the initial list of %s", definitely_offline_ips,
                 ips_to_check)
    return definitely_offline_ips


def set_up_logging():
    parser = argparse.ArgumentParser()
    parser.add_argument('-log',
                        '--loglevel',
                        default='info',
                        help='Provide logging level. Example --loglevel debug, default=info')
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel.upper())
    logging.info('Logging setup')


if __name__ == '__main__':
    set_up_logging()

    ip_ranges_to_scan, name, email, required_ips = load_config_values()
    all_active_ips = get_active_local_ips(ip_ranges_to_scan)
    logger.info('All active IPs: %s', all_active_ips)

    potentially_offline_ips = list(set(required_ips) - set(all_active_ips))
    offline_ips = ping_potentially_offline_ips(potentially_offline_ips)
    logger.info('Offline IPs %s', offline_ips)

    if offline_ips:
        send_email_notification(all_active_ips, offline_ips, name, email)
