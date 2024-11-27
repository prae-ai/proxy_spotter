#!/usr/bin/env python

import base64
import json
import logging
import os
import pandas as pd
import re
import uuid

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from deltalake import DeltaTable
from deltalake.writer import write_deltalake
from mitmproxy import http
from urllib.parse import urlparse

TARGET_URLS = {
# Example, where domain is the key and url pattern is the value
    'www.linkedin.com': '^/in/'
}

@dataclass
class RawHTML:
    """Base dataclass for capturing URL requests and responses"""
    @property
    def json(self) -> dict:
        return json.dumps(asdict(self))

    def set_datetime(self) -> None:
        """Apply a timestamp to the data"""
        now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.__dict__['datetime'] = now
    def set_uuid(self) -> None:
        """Generate a UUID based on the URL string"""
        self.__dict__['uuid'] = str(
            uuid.uuid5(uuid.NAMESPACE_URL, self.__dict__['url'])
        )

    def validate(self) -> None:
        """Validate field types are correct; pass for munging"""
        self.set_datetime()
        self.set_uuid()
        for f in fields(self):
            if self.__dict__[f.name] != None: # skip the defaults
                if f.type == str:
                    if not isinstance(self.__dict__[f.name], str):
                        raise Warning(
                            'Field "{}" should be of type str'.format(f.name)
                        )
                if f.type == int:
                    if not isinstance(self.__dict__[f.name], int):
                        raise Warning(
                            'Field "{}" should be of type int'.format(f.name)
                        )

    uuid     : str = field(default=None)
    body     : str = field(default=None)
    datetime : str = field(default=None)
    status   : int = field(default=None)
    url      : str = field(default=None)

class ProxySpotter:
    def __init__(self) -> None:
        """Create the local table when initialized"""
        self.home = os.environ['HOME']
        if 'Downloads' in os.listdir(self.home):
            self.data_path = f'{self.home}/Downloads'
        else:
            self.data_path = self.home
        if 'proxy_spotter' not in os.listdir(self.data_path):
                os.mkdir(f'{self.data_path}/proxy_spotter')
        self.data_path = '{0}/proxy_spotter/{1}_proxy_spotter.delta'.format(
            self.data_path,
            datetime.now(timezone.utc).strftime(
                '%Y-%m-%dT%H-%M-%S'
            )
        )

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            url = urlparse(flow.request.pretty_url)
            if url.netloc in TARGET_URLS.keys():
                method = flow.request.method
                if method == 'POST':
                    # Because UUIDs depend on full URLs being unique and 
                    # we probably want to gether information in the 
                    # request which may contain profile IDs add a base64 
                    # argument with the body to the full_url
                    post_body = base64.b64encode(
                        flow.request.text.encode('utf-8')
                    ).decode('utf-8')
                    full_url = '{0}?{1}'.format(
                        url.path, f'post_body={post_body}'
                    )
                    target = True
                elif method == 'GET':
                    if url.query != '':
                        full_url = '{0}?{1}'.format(url.path, url.query)
                    else:
                        full_url = url.path
                    target = True
                if method in ['GET', 'POST'] and re.search(
                    TARGET_URLS[url.netloc], full_url
                ):
                    logging.info(
                        f'[+ {type(self).__name__}] Found '\
                         'target {method} {full_url}'
                    )
                    raw_html = RawHTML()
                    raw_html.url = full_url
                    raw_html.body = flow.response.text
                    raw_html.status = flow.response.status_code
                    raw_html.validate()
                    logging.info(
                        f'[+ {type(self).__name__}] Adding to raw_html collect'
                    )
                    raw_html = pd.DataFrame([raw_html])
                    raw_html = raw_html.fillna('')
                    raw_html = pd.DataFrame(
                        raw_html,
                        columns=['uuid','datetime','url','status','body']
                    )
                    write_deltalake(self.data_path, raw_html, mode='append')
        except Exception as e:
            logging.error(f'[- {type(self).__name__}] Problem writing table')
            logging.exception(e)
            pass

# <--- Cheap and easy logger --->

from mitmproxy import log

class FileLog:
    def __init__(self, out='proxy_spotter.log'):
        self.logger = FileLogHandler(out)
        self.logger.install()

    def done(self):
        self.logger.file.close()
        self.logger.uninstall()


class FileLogHandler(log.MitmLogHandler):
    def __init__(self, out: str | None = None):
        super().__init__()
        self.file = open(out, 'a')

    def emit(self, record: logging.LogRecord) -> None:
        self.file.write(self.format(record))
        self.file.write('\n')

addons = [
    ProxySpotter(),
    FileLog()
]