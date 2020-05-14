import sys
from workflow import Workflow, ICON_WEB, web
from shodan import Shodan
from time import sleep
import socket
import re

def validate_domain(domain):
    regex = re.compile('^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$')
    match = regex.match(str(domain))
    return bool(match)


def validate_ip( ip):
    regex = re.compile(
        '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    match = regex.match(str(ip))
    return bool(match)

def get_service_info(ip):

        try:
            api = Shodan('KEY')
            ipinfo = api.host(ip)
        except:
            sys.exit(0)

        services = {}
        for service in ipinfo['data']:
            protocol = service['_shodan']['module']
            port = service['port']
            services.update({port: protocol})
        result =  services

        return result

def main(wf):
    host = wf.args[0]
    sleep(1)
    # print(sys.version)
    if validate_domain(host):
        host = socket.gethostbyname_ex(host)[2][0]
    elif validate_ip(host) :
        host = host
    else:
        return 0
    services = get_service_info(host)
    for port, protocol in services.items():
        wf.add_item(title=str(port),
                 subtitle=protocol,
                 icon=ICON_WEB)
    wf.send_feedback()


if __name__ == u"__main__":
    wf = Workflow()
    sys.exit(wf.run(main))