import requests

from colorama import Fore
from twisted.web import resource


class Webroot(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        print('{}[*] Got a GET request on path: {}'.format(Fore.GREEN, request.uri))
        return requests.get('https://account.spacetimestudios.com{}'.format(request.uri.decode('utf-8'))).text.encode('utf-8')
