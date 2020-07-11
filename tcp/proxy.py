from twisted.internet import reactor


used_ports = {}


def setup_proxy(server_adress, server_port, tcp_host, crypto, replay, frida_script, args):
    from tcp.server.factory import ServerFactory
    from tcp.server.endpoint import ServerEndpoint
    from tcp.client.endpoint import ClientEndpoint

    proxy_port = server_port

    if proxy_port in used_ports:
        if server_adress != used_ports[proxy_port]:
            while proxy_port in used_ports:
                proxy_port += 1

        else:
            print('[*] A TCP Proxy is already started on the same port with the same host, keeping it active !')
            return proxy_port

    client_endpoint = ClientEndpoint(reactor, server_adress, server_port)
    server_endpoint = ServerEndpoint(reactor, proxy_port)

    server_endpoint.listen(ServerFactory(client_endpoint, tcp_host, crypto, replay, frida_script, args))

    print("[*] Started a TCP Proxy on {}:{}".format(server_endpoint.interface, server_endpoint.port))

    used_ports[proxy_port] = server_adress
    return proxy_port
