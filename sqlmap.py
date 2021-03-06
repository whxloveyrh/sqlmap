#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import sys

sys.dont_write_bytecode = True

from lib.utils import versioncheck  # this has to be the first non-standard import

import bdb
import distutils
import glob
import inspect
import logging
import os
import re
import shutil
import sys
import thread
import threading
import time
import traceback
import warnings

warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
warnings.filterwarnings(action="ignore", category=DeprecationWarning)

from lib.core.data import logger

try:
    from lib.controller.controller import start
    from lib.core.common import banner
    from lib.core.common import createGithubIssue
    from lib.core.common import dataToStdout
    from lib.core.common import getSafeExString
    from lib.core.common import getUnicode
    from lib.core.common import maskSensitiveData
    from lib.core.common import setPaths
    from lib.core.common import weAreFrozen
    from lib.core.data import cmdLineOptions
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.data import paths
    from lib.core.common import unhandledExceptionMessage
    from lib.core.common import MKSTEMP_PREFIX
    from lib.core.exception import SqlmapBaseException
    from lib.core.exception import SqlmapShellQuitException
    from lib.core.exception import SqlmapSilentQuitException
    from lib.core.exception import SqlmapUserQuitException
    from lib.core.option import initOptions
    from lib.core.option import init
    from lib.core.profiling import profile
    from lib.core.settings import IS_WIN
    from lib.core.settings import LEGAL_DISCLAIMER
    from lib.core.settings import THREAD_FINALIZATION_TIMEOUT
    from lib.core.settings import VERSION
    from lib.core.testing import smokeTest
    from lib.core.testing import liveTest
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.api import setRestAPILog
    from lib.utils.api import StdDbOut
except KeyboardInterrupt:  # Ctrl+C被按下
    errMsg = "user aborted"
    logger.error(errMsg)

    raise SystemExit

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if weAreFrozen() else __file__
    except NameError:  # 尝试访问一个未声明的变量，所抛出的异常
        _ = inspect.getsourcefile(modulePath)

    return getUnicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding())


def checkEnvironment():
    paths.SQLMAP_ROOT_PATH = modulePath()

    try:
        os.path.isdir(paths.SQLMAP_ROOT_PATH)
    except UnicodeEncodeError:
        errMsg = "your system does not properly handle non-ASCII paths. "
        errMsg += "Please move the sqlmap's directory to the other location"
        logger.critical(errMsg)
        raise SystemExit

    if distutils.version.LooseVersion(VERSION) < distutils.version.LooseVersion("1.0"):
        errMsg = "your runtime environment (e.g. PYTHONPATH) is "
        errMsg += "broken. Please make sure that you are not running "
        errMsg += "newer versions of sqlmap with runtime scripts for older "
        errMsg += "versions"
        logger.critical(errMsg)
        raise SystemExit

def main():
    """
    Main function of sqlmap when running from command line.
    http://python.usyiyi.cn/
    http://blog.csdn.net/pipisorry/article/details/39909057/
    python异常类型:http://www.cnblogs.com/zhangpengshou/p/3565087.html
    """

    try:
        checkEnvironment()  # 检查系统环境

        setPaths()          # 设置路径
        banner()            # 打印sqlmap标识信息

        '''
        cmdLineParser()解析命令行参数
        '''
        # Store original command line options for possible later restoration
        cmdLineOptions.update(cmdLineParser().__dict__)
        initOptions(cmdLineOptions)

        if hasattr(conf, "api"):  # hasattr用于确定一个对象是否具有某一个属性
            '''
            语法：
            hasattr(object,name)->bool
            判断object中是否有name属性,返回一个布尔值，如果有name属性，则返回为True,否则返回为False
            '''
            # Overwrite system standard output and standard error to write
            # to an IPC database
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")
            setRestAPILog()

        conf.showTime = True
        dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] starting at %s\n\n" % time.strftime("%X"), forceOutput=True)

        init()  # 初始化环境信息

        if conf.profile:
            profile()    # sqlmap程序运行时的环境信息
        elif conf.smokeTest:
            smokeTest()  # 冒烟测试
        elif conf.liveTest:
            liveTest()   # 存活测试
        else:
            try:
                start()   # 检测开始的地方，start()函数位于controller.py中
            except thread.error as ex:
                if "can't start new thread" in getSafeExString(ex):
                    errMsg = "unable to start new threads. Please check OS (u)limits"
                    logger.critical(errMsg)
                    raise SystemExit
                else:
                    raise

    except SqlmapUserQuitException:
        errMsg = "user quit"
        try:
            logger.error(errMsg)
            '''
            os._exit() 直接退出 Python 解释器，其后的代码都不执行。
            sys.exit() 引发一个 SystemExit 异常，没有捕获这个异常，会直接退出；捕获这个异常可以做一些额外的清理工作。
            exit() 跟 C 语言等其他语言的 exit() 应该是一样的。

            Python退出程序的方式有两种：os._exit()， sys.exit()
            1）os._exit() 直接退出 Python程序，其后的代码也不会继续执行。
            2）sys.exit() 引发一个 SystemExit异常，若没有捕获这个异常，Python解释器会直接退出；捕获这个异常可以做一些额外的清理工作。0为正常退出，其他数值（1-127）为不正常，可抛异常事件供捕获。
            3) exit() 跟 C 语言等其他语言的 exit() 应该是一样的。
            os._exit() 调用 C 语言的 _exit() 函数。
            __builtin__.exit 是一个 Quitter 对象，这个对象的 __call__ 方法会抛出一个 SystemExit 异常。
            一般来说
            os._exit() 用于在线程中退出
            sys.exit() 用于在主线程中退出。
            '''
        except KeyboardInterrupt:  # Ctrl+C被按下
            pass

    except (SqlmapSilentQuitException, bdb.BdbQuit):
        pass

    except SqlmapShellQuitException:
        cmdLineOptions.sqlmapShell = False

    except SqlmapBaseException as ex:
        errMsg = getSafeExString(ex)
        try:
            logger.critical(errMsg)
        except KeyboardInterrupt:  # Ctrl+C被按下
            pass
        raise SystemExit

    except KeyboardInterrupt:  # Ctrl+C被按下
        print

        errMsg = "user aborted"
        try:
            logger.error(errMsg)
        except KeyboardInterrupt:  # Ctrl+C被按下
            pass

    except EOFError:  # 遇到文件末尾引发的异常
        print
        errMsg = "exit"

        try:
            logger.error(errMsg)
        except KeyboardInterrupt:  # Ctrl+C被按下
            pass

    except SystemExit:
        pass

    except:
        print
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()

        try:
            if any(_ in excMsg for _ in ("No space left", "Disk quota exceeded")):
                errMsg = "no space left on output device"
                logger.error(errMsg)
                raise SystemExit

            elif "_mkstemp_inner" in excMsg:
                errMsg = "there has been a problem while accessing temporary files"
                logger.error(errMsg)
                raise SystemExit

            elif "can't start new thread" in excMsg:
                errMsg = "there has been a problem while creating new thread instance. "
                errMsg += "Please make sure that you are not running too many processes"
                if not IS_WIN:
                    errMsg += " (or increase the 'ulimit -u' value)"
                logger.error(errMsg)
                raise SystemExit

            elif all(_ in excMsg for _ in ("pymysql", "configparser")):
                errMsg = "wrong initialization of pymsql detected (using Python3 dependencies)"
                logger.error(errMsg)
                raise SystemExit

            elif "bad marshal data (unknown type code)" in excMsg:
                match = re.search(r"\s*(.+)\s+ValueError", excMsg)
                errMsg = "one of your .pyc files are corrupted%s" % (" ('%s')" % match.group(1) if match else "")
                errMsg += ". Please delete .pyc files on your system to fix the problem"
                logger.error(errMsg)
                raise SystemExit

            elif "valueStack.pop" in excMsg and kb.get("dumpKeyboardInterrupt"):
                raise SystemExit

            for match in re.finditer(r'File "(.+?)", line', excMsg):
                file_ = match.group(1)
                file_ = os.path.relpath(file_, os.path.dirname(__file__))
                file_ = file_.replace("\\", '/')
                file_ = re.sub(r"\.\./", '/', file_).lstrip('/')
                excMsg = excMsg.replace(match.group(1), file_)

            errMsg = maskSensitiveData(errMsg)
            excMsg = maskSensitiveData(excMsg)

            if hasattr(conf, "api"):
                logger.critical("%s\n%s" % (errMsg, excMsg))
            else:
                logger.critical(errMsg)
                kb.stickyLevel = logging.CRITICAL
                dataToStdout(excMsg)
                createGithubIssue(errMsg, excMsg)

        except KeyboardInterrupt:  # Ctrl+C被按下
            pass

    finally:
        kb.threadContinue = False
        kb.threadException = True

        if conf.get("showTime"):
            dataToStdout("\n[*] shutting down at %s\n\n" % time.strftime("%X"), forceOutput=True)

        '''
        返回所有匹配的文件路径列表。例如，
        >>> import glob
        >>> print glob.glob(r'*.py')
        ['sqlmap.py', 'sqlmapapi.py']
        >>> print glob.glob(r'*.py');
        ['sqlmap.py', 'sqlmapapi.py']
        >>> print glob.glob(r'E:\SQLMap\*.py')
        ['E:\\SQLMap\\sqlmap.py', 'E:\\SQLMap\\sqlmapapi.py']
        >>>
        '''
        if kb.get("tempDir"):  #kb是一个字典
                for prefix in (MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING, MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                    for filepath in glob.glob(os.path.join(kb.tempDir, "%s*" % prefix)):
                        try:
                            os.remove(filepath)
                        except OSError:
                            pass
                if not filter(None, (filepath for filepath in glob.glob(os.path.join(kb.tempDir, '*')) if not any(filepath.endswith(_) for _ in ('.lock', '.exe', '_')))):
                    shutil.rmtree(kb.tempDir, ignore_errors=True)

        if conf.get("hashDB"):   #conf是一个字典
            try:
                conf.hashDB.flush(True)
            except KeyboardInterrupt:  # Ctrl+C被按下
                pass

        if cmdLineOptions.get("sqlmapShell"):
            cmdLineOptions.clear()
            conf.clear()
            kb.clear()
            main()

        if hasattr(conf, "api"):
            try:
                conf.database_cursor.disconnect()
            except KeyboardInterrupt:  # Ctrl+C被按下
                pass

        if conf.get("dumper"):
            conf.dumper.flush()

        # short delay for thread finalization
        try:
            _ = time.time()
            while threading.activeCount() > 1 and (time.time() - _) > THREAD_FINALIZATION_TIMEOUT:
                time.sleep(0.01)
        except KeyboardInterrupt:  # Ctrl+C被按下
            pass

        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if threading.activeCount() > 1:
            os._exit(0)
'''
当我们在命令行运行sqlmap模块文件时，Python解释器把一个特殊变量__name__置为__main__，
而如果在其他地方导入该sqlmap模块时，if判断将失败，
因此，这种if测试可以让一个模块通过命令行运行时执行一些额外的代码，最常见的就是运行测试。

'''
if __name__ == "__main__":
    main()
