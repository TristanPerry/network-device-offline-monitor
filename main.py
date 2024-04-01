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

    # TODO validate

    return to_list(to_scan), notification_name, notification_email, to_list(required_ips)


def get_active_local_ips(to_scan: list) -> list:
    # nmap 192.168.7.0/24
    nmap = nmap3.NmapHostDiscovery()
    active_ips_in_range = []

    for host in to_scan:
        logger.info('Scanning host range %s', host)
        results = nmap.nmap_arp_discovery(host)
        logger.debug('Results for host range %s', host)
        logger.debug(results)

        up_ips = {ip: result for ip, result in results.items() if
                  'state' in result and result['state']['state'] == 'up'}

        up_ips_list = list(up_ips.keys())
        logger.debug('%s IPs are UP for host range %s', up_ips_list, host)
        active_ips_in_range.extend(up_ips_list)

    return active_ips_in_range


def send_email_notification(error_ips: list, notification_name: str, notification_email: str) -> None:
    logger.error('IP(s) %s are offline, sending email to %s', error_ips, notification_email)
    mailer = emails.NewEmail(os.getenv('MAILERSEND_API_KEY'))

    mail_body = {}

    mail_from = {
        "name": "Offline Notifier",
        "email": "noreply@techoverwrite.com",
    }

    recipients = [
        {
            "name": notification_name,
            "email": notification_email,
        }
    ]

    reply_to = [
        {
            "name": "No Reply",
            "email": "noreply@techoverwrite.com",
        }
    ]

    mailer.set_mail_from(mail_from, mail_body)
    mailer.set_mail_to(recipients, mail_body)
    mailer.set_reply_to(reply_to, mail_body)
    mailer.set_subject("Network Device(s) Offline", mail_body)
    mailer.set_plaintext_content("Warning: the following required IP addresses are offline: " + ', '.join(error_ips),
                                 mail_body)

    response = mailer.send(mail_body)
    logger.debug("Email response: %s", response)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-log',
                        '--loglevel',
                        default='warning',
                        help='Provide logging level. Example --loglevel debug, default=info')
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel.upper())
    logging.info('Logging setup')

    ip_ranges_to_scan, name, email, required_ips = load_config_values()
    all_active_ips = get_active_local_ips(ip_ranges_to_scan)
    logger.info('All active IPs: %s', all_active_ips)

    offline_ips = list(set(required_ips) - set(all_active_ips))
    logger.info('Offline IPs %s', offline_ips)

    if offline_ips:
        send_email_notification(offline_ips, name, email)
