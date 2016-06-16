#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import logging
import optparse
import sys

sys.dont_write_bytecode = True

from lib.utils import versioncheck  # this has to be the first non-standard import

from sqlmap import modulePath
from lib.core.common import setPaths
from lib.core.data import paths
from lib.core.data import logger
from lib.core.settings import RESTAPI_DEFAULT_ADAPTER
from lib.core.settings import RESTAPI_DEFAULT_ADDRESS
from lib.core.settings import RESTAPI_DEFAULT_PORT
from lib.utils.api import client
from lib.utils.api import server
'''
利用sqlmap测试SQL注入的效率很低,每一个url都需要手动测试,这样肯定不是理想状态。
sqlmap的作者肯定也察觉到这一点了,默默的开发了sqlmapapi.py,当你使用了sqlmapapi.py后才能体会到sqlmap的强大。
sqlmap构建了一个自动化 分布式的扫描帝国!主要从sqlmapapi.py的代码角度和AutoSqli类的设计与实现的角度展开。
参考网站地址：http://drops.wooyun.org/tips/6653
'''
def main():
    """
    REST-JSON API main function
    """

    # Set default logging level to debug
    logger.setLevel(logging.DEBUG)

    # Initialize path variable
    paths.SQLMAP_ROOT_PATH = modulePath()
    setPaths()

    # Parse command line options
    apiparser = optparse.OptionParser()
    apiparser.add_option("-s", "--server", help="Act as a REST-JSON API server", default=RESTAPI_DEFAULT_PORT, action="store_true")
    apiparser.add_option("-c", "--client", help="Act as a REST-JSON API client", default=RESTAPI_DEFAULT_PORT, action="store_true")
    apiparser.add_option("-H", "--host", help="Host of the REST-JSON API server", default=RESTAPI_DEFAULT_ADDRESS, action="store")
    apiparser.add_option("-p", "--port", help="Port of the the REST-JSON API server", default=RESTAPI_DEFAULT_PORT, type="int", action="store")
    apiparser.add_option("--adapter", help="Server (bottle) adapter to use (default %s)" % RESTAPI_DEFAULT_ADAPTER, default=RESTAPI_DEFAULT_ADAPTER, action="store")
    (args, _) = apiparser.parse_args()

    # Start the client or the server
    if args.server is True:
        server(args.host, args.port, adapter=args.adapter)
    elif args.client is True:
        client(args.host, args.port)
    else:
        apiparser.print_help()

if __name__ == "__main__":
    main()
