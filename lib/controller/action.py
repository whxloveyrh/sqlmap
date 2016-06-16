#!/usr/bin/env python
#-*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.controller.handler import setHandler
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import CONTENT_TYPE
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.settings import SUPPORTED_DBMS
from lib.techniques.brute.use import columnExists
from lib.techniques.brute.use import tableExists

def action():
    """
    This function exploit the SQL injection on the affected
    URL parameter and extract requested data from the
    back-end database management system or operating system
    if possible
    """

    # First of all we have to identify the back-end database management
    # system to be able to go ahead with the injection
    setHandler()

    if not Backend.getDbms() or not conf.dbmsHandler:
        htmlParsed = Format.getErrorParsedDBMSes()

        errMsg = "sqlmap was not able to fingerprint the "
        errMsg += "back-end database management system"

        if htmlParsed:
            errMsg += ", but from the HTML error page it was "
            errMsg += "possible to determinate that the "
            errMsg += "back-end DBMS is %s" % htmlParsed

        if htmlParsed and htmlParsed.lower() in SUPPORTED_DBMS:
            errMsg += ". Do not specify the back-end DBMS manually, "
            errMsg += "sqlmap will fingerprint the DBMS for you"
        elif kb.nullConnection:
            errMsg += ". You can try to rerun without using optimization "
            errMsg += "switch '%s'" % ("-o" if conf.optimize else "--null-connection")

        raise SqlmapUnsupportedDBMSException(errMsg)

    conf.dumper.singleString(conf.dbmsHandler.getFingerprint())

    #参考网站地址：http://drops.wooyun.org/tips/143
    # Enumeration options
    '''标志
    参数：-b,--banner
    大多数的数据库系统都有一个函数可以返回数据库的版本号，通常这个函数是version()或者变量@@version这主要取决与是什么数据库。
    '''
    if conf.getBanner:
        conf.dumper.banner(conf.dbmsHandler.getBanner())

    '''用户
    参数：-current-user
    在大多数据库中可以获取到管理数据的用户。
    '''
    if conf.getCurrentUser:
        conf.dumper.currentUser(conf.dbmsHandler.getCurrentUser())

    '''当前数据库
    参数：--current-db
    返还当前连接的数据库。
    '''
    if conf.getCurrentDb:
        conf.dumper.currentDb(conf.dbmsHandler.getCurrentDb())

    if conf.getHostname:
        conf.dumper.hostname(conf.dbmsHandler.getHostname())

    '''当前用户是否为管理员
    参数：--is-dba
    判断当前的用户是否为管理，是的话会返回True。
    '''
    if conf.isDba:
        conf.dumper.dba(conf.dbmsHandler.isDba())

    '''列数据库管理用户
    参数：--users
    当前用户有权限读取包含所有用户的表的权限时，就可以列出所有管理用户。
    '''
    if conf.getUsers:
        conf.dumper.users(conf.dbmsHandler.getUsers())

    '''列出并破解数据库用户的hash
    参数：--passwords
    当前用户有权限读取包含用户密码的彪的权限时，sqlmap会现列举出用户，然后列出hash，并尝试破解。
    也可以提供-U参数来指定爆破哪个用户的hash。
    '''
    if conf.getPasswordHashes:
        try:
            conf.dumper.userSettings("database management system users password hashes",
                                    conf.dbmsHandler.getPasswordHashes(), "password hash", CONTENT_TYPE.PASSWORDS)
        except SqlmapNoneDataException, ex:
            logger.critical(ex)
        except:
            raise

    '''列出数据库管理员权限
    参数：--privileges
    当前用户有权限读取包含所有用户的表的权限时，很可能列举出每个用户的权限，
    sqlmap将会告诉你哪个是数据库的超级管理员。也可以用-U参数指定你想看哪个用户的权限。
    '''
    if conf.getPrivileges:
        try:
            conf.dumper.userSettings("database management system users privileges",
                                    conf.dbmsHandler.getPrivileges(), "privilege", CONTENT_TYPE.PRIVILEGES)
        except SqlmapNoneDataException, ex:
            logger.critical(ex)
        except:
            raise

    '''列出数据库管理员角色
    参数：--roles
    当前用户有权限读取包含所有用户的表的权限时，很可能列举出每个用户的角色，
    也可以用-U参数指定你想看哪个用户的角色。仅适用于当前数据库是Oracle的时候。
    '''
    if conf.getRoles:
        try:
            conf.dumper.userSettings("database management system users roles",
                                    conf.dbmsHandler.getRoles(), "role", CONTENT_TYPE.ROLES)
        except SqlmapNoneDataException, ex:
            logger.critical(ex)
        except:
            raise

    '''列出数据库系统的数据库
    参数：--dbs
    当前用户有权限读取包含所有数据库列表信息的表中的时候，即可列出所有的数据库。
    '''
    if conf.getDbs:
        conf.dumper.dbs(conf.dbmsHandler.getDbs())

    '''列举数据库表
    参数：--tables,--exclude-sysdbs,-D
    当前用户有权限读取包含所有数据库表信息的表中的时候，即可列出一个特定数据的所有表。
    如果你不提供-D参数来列指定的一个数据的时候，sqlmap会列出数据库所有库的所有表。
    --exclude-sysdbs参数是指包含了所有的系统数据库。
    需要注意的是在Oracle中你需要提供的是TABLESPACE_NAME而不是数据库名称。
    '''
    if conf.getTables:
        conf.dumper.dbTables(conf.dbmsHandler.getTables())

    '''列举数据库表中的字段 暴力破解表名
    参数：--common-tables
    当使用--tables无法获取到数据库的表时，可以使用此参数。
    通常是如下情况：
    1、MySQL数据库版本小于5.0，没有information_schema表。
    2、数据库是Microssoft Access，系统表MSysObjects是不可读的（默认）。
    3、当前用户没有权限读取系统中保存数据结构的表的权限。
    暴力破解的表在txt/common-tables.txt文件中，你可以自己添加。
    '''
    if conf.commonTables:
        conf.dumper.dbTables(tableExists(paths.COMMON_TABLES))

    '''列举数据库系统的架构
    参数：--schema,--exclude-sysdbs
    用户可以用此参数获取数据库的架构，包含所有的数据库，表和字段，以及各自的类型。
    加上--exclude-sysdbs参数，将不会获取数据库自带的系统库内容。
    '''
    if conf.getSchema:
        conf.dumper.dbTableColumns(conf.dbmsHandler.getSchema(), CONTENT_TYPE.SCHEMA)

    '''
    参数：--columns,-C,-T,-D
    当前用户有权限读取包含所有数据库表信息的表中的时候，即可列出指定数据库表中的字段，同时也会列出字段的数据类型。
    如果没有使用-D参数指定数据库时，默认会使用当前数据库。
    '''
    if conf.getColumns:
        conf.dumper.dbTableColumns(conf.dbmsHandler.getColumns(), CONTENT_TYPE.COLUMNS)

    '''获取表中数据个数
    参数：--count
    有时候用户只想获取表中的数据个数而不是具体的内容，那么就可以使用这个参数。
    '''
    if conf.getCount:
        conf.dumper.dbTablesCount(conf.dbmsHandler.getCount())

    '''暴力破解列名
    参数：--common-columns
    与暴力破解表名一样，暴力跑的列名在txt/common-columns.txt中。
    '''
    if conf.commonColumns:
        conf.dumper.dbTableColumns(columnExists(paths.COMMON_COLUMNS))

    '''获取整个表的数据
    参数：--dump,-C,-T,-D,--start,--stop,--first,--last
    如果当前管理员有权限读取数据库其中的一个表的话，那么就能获取真个表的所有内容。
    使用-D,-T参数指定想要获取哪个库的哪个表，不适用-D参数时，默认使用当前库。
    可以获取指定库中的所有表的内容，只用-dump跟-D参数（不使用-T与-C参数）。
    也可以用-dump跟-C获取指定的字段内容。
    '''
    if conf.dumpTable:
        conf.dbmsHandler.dumpTable()

    '''获取所有数据库表的内容
    参数：--dump-all,--exclude-sysdbs
    使用--dump-all参数获取所有数据库表的内容，可同时加上--exclude-sysdbs只获取用户数据库的表，
    需要注意在Microsoft SQL Server中master数据库没有考虑成为一个系统数据库，
    因为有的管理员会把他当初用户数据库一样来使用它。
    '''
    if conf.dumpAll:
        conf.dbmsHandler.dumpAll()

    '''搜索字段，表，数据库
    参数：--search,-C,-T,-D
    --search可以用来寻找特定的数据库名，所有数据库中的特定表名，所有数据库表中的特定字段。
    可以在一下三种情况下使用：
    -C后跟着用逗号分割的列名，将会在所有数据库表中搜索指定的列名。
    -T后跟着用逗号分割的表名，将会在所有数据库中搜索指定的表名
    -D后跟着用逗号分割的库名，将会在所有数据库中搜索指定的库名。
    '''
    if conf.search:
        conf.dbmsHandler.search()

    '''运行自定义的SQL语句
    参数：--sql-query,--sql-shell
    sqlmap会自动检测确定使用哪种SQL注入技术，如何插入检索语句。
    如果是SELECT查询语句，sqlap将会输出结果。如果是通过SQL注入执行其他语句，需要测试是否支持多语句执行SQL语句。
    '''
    if conf.query:
        conf.dumper.query(conf.query, conf.dbmsHandler.sqlQuery(conf.query))

    if conf.sqlShell:
        conf.dbmsHandler.sqlShell()

    if conf.sqlFile:
        conf.dbmsHandler.sqlFile()

    '''用户自定义函数注入
    参数：--udf-inject,--shared-lib
    你可以通过编译MySQL注入你自定义的函数（UDFs）或PostgreSQL在windows中共享库，DLL，或者Linux/Unix中共享对象，
    sqlmap将会问你一些问题，上传到服务器数据库自定义函数，然后根据你的选择执行他们，当你注入完成后，sqlmap将会移除它们。
    '''
    # User-defined function options
    if conf.udfInject:
        conf.dbmsHandler.udfInjectCustom()

    '''从数据库服务器中读取文件
    参数：--file-read
    当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数。
    读取的文件可以是文本也可以是二进制文件。
    '''
    # File system options
    if conf.rFile:
        conf.dumper.rFile(conf.dbmsHandler.readFile(conf.rFile))

    '''把文件上传到数据库服务器中
    参数：--file-write,--file-dest
    当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数。
    上传的文件可以是文本也可以是二进制文件。
    '''
    if conf.wFile:
        conf.dbmsHandler.writeFile(conf.wFile, conf.dFile, conf.wFileType)

    '''运行任意操作系统命令
    参数：--os-cmd,--os-shell
    当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数。
    在MySQL、PostgreSQL，sqlmap上传一个二进制库，包含用户自定义的函数，sys_exec()和sys_eval()。
    那么他创建的这两个函数可以执行系统命令。在Microsoft SQL Server，sqlmap将会使用xp_cmdshell存储过程，
    如果被禁（在Microsoft SQL Server 2005及以上版本默认禁制），sqlmap会重新启用它，如果不存在，会自动创建。
    '''
    # Operating system options
    if conf.osCmd:
        conf.dbmsHandler.osCmd()

    '''
    用--os-shell参数也可以模拟一个真实的shell，可以输入你想执行的命令。
    当不能执行多语句的时候（比如php或者asp的后端数据库为MySQL时），仍然可能使用INTO OUTFILE写进可写目录，
    来创建一个web后门。支持的语言：
    1、ASP
    2、ASP.NET
    3、JSP
    4、PHP
    '''
    if conf.osShell:
        conf.dbmsHandler.osShell()

    '''Meterpreter配合使用
    参数：--os-pwn,--os-smbrelay,--os-bof,--priv-esc,--msf-path,--tmp-path
    当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数，
    可以在数据库与攻击者直接建立TCP连接，这个连接可以是一个交互式命令行的Meterpreter会话，
    sqlmap根据Metasploit生成shellcode，并有四种方式执行它：
    1、通过用户自定义的sys_bineval()函数在内存中执行Metasplit的shellcode，支持MySQL和PostgreSQL数据库，参数：--os-pwn。
    2、通过用户自定义的函数上传一个独立的payload执行，MySQL和PostgreSQL的sys_exec()函数，Microsoft SQL Server的xp_cmdshell()函数，参数：--os-pwn。
    3、通过SMB攻击(MS08-068)来执行Metasploit的shellcode，当sqlmap获取到的权限足够高的时候（Linux/Unix的uid=0，Windows是Administrator），--os-smbrelay。
    4、通过溢出Microsoft SQL Server 2000和2005的sp_replwritetovarbin存储过程(MS09-004)，在内存中执行Metasploit的payload，参数：--os-bof

    '''
    if conf.osPwn:
        conf.dbmsHandler.osPwn()

    if conf.osSmb:
        conf.dbmsHandler.osSmb()

    if conf.osBof:
        conf.dbmsHandler.osBof()

    # Windows registry options
    if conf.regRead:
        conf.dumper.registerValue(conf.dbmsHandler.regRead())

    if conf.regAdd:
        conf.dbmsHandler.regAdd()

    if conf.regDel:
        conf.dbmsHandler.regDel()

    # Miscellaneous options
    if conf.cleanup:
        conf.dbmsHandler.cleanup()

    if conf.direct:
        conf.dbmsConnector.close()
