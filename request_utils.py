import requests

def prepare_and_send_request(method, url, headers=None, data=None, proxies=None):
    session = requests.Session()

    req = requests.Request(
        method=method,
        url=url,
        headers=headers,
        data=data
    )

    prepared = session.prepare_request(req)
    response = session.send(prepared, proxies=proxies)

    return prepared, response
