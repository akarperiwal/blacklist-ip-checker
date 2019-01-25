import urllib3, argparse, dns.resolver

http = urllib3.PoolManager()


def checkblacklist(ip):
    bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net",
           "blacklist.woody.ch", "cbl.abuseat.org", "cdl.anti-spam.org.cn",
           "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info",
           "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
           "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
           "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch",
           "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru",
           "dyna.spamrats.com", "dynip.rothen.com",
           "http.dnsbl.sorbs.net", "images.rbl.msrbl.net",
           "ips.backscatterer.org", "ix.dnsbl.manitu.net",
           "korea.services.net", "misc.dnsbl.sorbs.net",
           "noptr.spamrats.com", "ohps.dnsbl.net.au", "omrs.dnsbl.net.au",
           "orvedb.aupads.org", "osps.dnsbl.net.au", "osrs.dnsbl.net.au",
           "owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
           "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net",
           "rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.nether.net",
           "residential.block.transip.nl", "ricn.dnsbl.net.au",
           "rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net",
           "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net",
           "spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch",
           "t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de",
           "torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com",
           "ubl.unsubscore.com", "virus.rbl.jp", "virus.rbl.msrbl.net",
           "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
           "zen.spamhaus.org", "zombie.dnsbl.sorbs.net"]

    GOOD = []
    BAD = []
    total = 0
    failed = 0
    for bl in bls:

        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(ip).split("."))) + "." + bl
            my_resolver.timeout = 5
            my_resolver.lifetime = 5
            answers = my_resolver.query(query, "A")
            answer_txt = my_resolver.query(query, "TXT")
            BAD.append("Blacklisted at %s : %s" % (bl, answer_txt[0]))
            total = total + 1

        except dns.resolver.NXDOMAIN:
            GOOD.append(bl)
            total = total + 1

        except dns.resolver.Timeout:
            failed = failed + 1

        except dns.resolver.NoNameservers:
            failed = failed + 1

        except dns.resolver.NoAnswer:
            failed = failed + 1

    print("Black-List report for IP {0}".format(ip))
    print("White Listed in %d" % (len(GOOD)))
    print("Black Listed in %d" % (len(BAD)))
    for i in BAD:
        print(i)
    print("Failed in %d" % (failed))


if __name__ == "__main__":
    iplists = []
    parser = argparse.ArgumentParser(description='Black List IP Checked - Akar Periwal')
    parser.add_argument('-i', '--ip', help='IP address to check')
    parser.add_argument('-f', '--file', help='IP address to check')
    parser.add_argument('--success', help='Also display GOOD', required=False, action="store_true")
    args = parser.parse_args()
    if args is not None and args.ip is not None and len(args.ip) > 0:
        badip = args.ip
        iplists.append(badip)
    else:
        if args is not None and args.file is not None and len(args.file) > 0:
            for i in open(args.file):
                iplists.append(i.rstrip())
        else:
            my_ip = http.request('GET', 'http://icanhazip.com').data.rstrip().decode("utf-8")
            print('Your public IP address is %s\n' % (my_ip))
            # Get IP To Check
            resp = input('Would you like to check {0} ? (Y/N):'.format(my_ip))
            if resp.lower() in ["yes", "y"]:
                badip = my_ip
            else:
                badip = input(blue("\nWhat IP would you like to check?: "))
                if badip is None or badip == "":
                    sys.exit("No IP address to check.")
            iplists.append(badip)
    for i in iplists:
        checkblacklist(i)
