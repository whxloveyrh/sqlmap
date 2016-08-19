1. Google dork的作用和 Google site:
2. [认识SQL注入的类型](http://www.codesec.net/view/211276.html)
<br>SQL注入的原理:用户在正常请求中伪造一些程序命令,绕过防火墙,传输到相应的应用程序中,进入数据库中。从而执行一些非授权的SQL代码,以此达到修改、窃取或者破坏数据库信息的目的。
<br>[SQL注入分类](www.freebuf.com/articles/web/98119.html)
    <br>1. 注入途径分类
        <br>&emsp;&emsp;1. 通过WEB端对数据库进行注入攻击
        <br>&emsp;&emsp;2. 直接访问数据库进行注入攻击
    <br>2. 注入方式分类
        <br>&emsp;&emsp;1. SQL Manipulation
        <br>&emsp;&emsp;2. Code Injection
        <br>&emsp;&emsp;3. Function Call Injection
        <br>&emsp;&emsp;4. Buffer Overflows
    SQL Manipulation和Code Injection多出现在WEB端的SQL注入上面。
    Function Call Injection 和 Buffer Overflows主要用于直接对数据库自身进行攻击的方式,对数据库的安全威胁更加致命。
3. BISECTION METHOD
4. http:
    <br>&emsp;&emsp;doc:        项目的一些说明文档,主要包括作者信息、修改日志、版权申明、常见问题、用户手册等等
    <br>&emsp;&emsp;extra:      项目所需的额外文件
    <br>&emsp;&emsp;lib:        项目核心实现文件夹
    <br>&emsp;&emsp;plugins:    项目的插件,主要包括连接数据库、枚举数据库信息,接管数据库
    <br>&emsp;&emsp;procs:      项目所需要使用的存储过程
    <br>&emsp;&emsp;shell:      项目shell相关的信息
    <br>&emsp;&emsp;tamper:     项目进行注入的时候,绕过防火墙的一些基本伪装技术
    <br>&emsp;&emsp;thirdparty: 项目的第三方库文件,主要包括后台颜色输出控制
    <br>&emsp;&emsp;txt:        项目进行暴力破解所需要的文件,主要包括常见列名、常见表名、常见的输出、用户代理、密码字典等等
    <br>&emsp;&emsp;udf:        项目的用户自定义功能函数,主要用于在后台数据库系统中执行
    <br>&emsp;&emsp;waf:        项目目前能够是别的防火墙种类型信息
    <br>&emsp;&emsp;xml:        项目进行注入需要使用的信息,主要包括注入的payload、边界选择条件、数据库识别的报错信息、查询数据库使用的信息
    <br>&emsp;&emsp;.gitattributes 版本控制相关的信息
    <br>&emsp;&emsp;.gitgnore      版本控制时,进行忽略的信息
    <br>&emsp;&emsp;.travis.yml:   项目版本信息
    <br>&emsp;&emsp;readme.md:     项目的用户手册
    <br>&emsp;&emsp;sqlmap.conf:   项目的默认配置信息
    <br>&emsp;&emsp;sqlmap.py      项目测试入口
    <br>&emsp;&emsp;sqlmapapi.py   项目测试入口
<br>git 创建 .gitignore 文件 建立项目过滤规则

5. [ .gitignore](http://blog.csdn.net/liuqiaoyu080512/article/details/8648266)

Git 可以管理所有文件的变更， 但并不是所有文件都有意义。

    5.1. 大部分二进制文件没有意义
　　      比如说 VC 工程的 Debug 和 Release 文件夹下的文件， 或者 Java 项目的 bin 文件夹中的 class 文件， 
         这些文件都是基于源代码生成的， 只要有源代码就能生成出来，所以版本管理的时候应该忽略它们。

    5.2. 有些文本文件也没有意义
　　      比如说 VC 工程中的 .plg 文件， 它是个 html 格式的文本文件， 保存了编译后产生的 error 和 warning， 显然没有进行版本管理的必要。

    5.3. 有些二进制文件不能忽略
　　      比如说 MFC 工程的 res\Toolbar.bmp， 是工具栏的位图文件，二进制文件， 如果忽略，工程就不完整了，别人 clone 你的版本库后用不了。 而这些文件一般不频繁变更，进行版本管理也不浪费空间。
　　      总之，能从别的文件生成的文件就应该被忽略。 要忽略这些文件，一般在 .gitignore 中设置规则， 如下是一篇对 .gitignore 介绍得很好的文章

6. [浅识 .gitattributes](https://www.jmlog.com/recognize-gitattributes/)
<br>.gitattributes 位于 Git 仓库的根目录下，用于对特定文件的属性进行设定。
<br>* text=auto
默认设置所有文件是文本类型时，Checkout 时换行符转换为 Unix 换行符 LF，不是文本类型时，不作改变。
<br>.vimrc text eol=lf
<br>.gvimrc text eol=lf
<br>*.vim text eol=lf
<br>强制将 Vim 的配置文件的换行符转换为 Unix 换行符 LF。
<br>*.rb diff=ruby
<br>*.tex diff=tex
根据不同类型指定不同的 diff 模式，diff 时更美观。
<br>*.png binary -delta
<br>*.jpeg binary -delta
<br>*.jpg binary -delta
<br>*.gif binary -delta
<br>*.gz binary -delta
<br>*.bz2 binary -delta
<br>*.tgz binary -delta
<br>对于二进制文件，指定 binary 属性，等价于 -text -diff，含义不言而喻。
-delta 让 Git 在 pack 时不进行压缩，减少 git commit 等操作时的系统时间消耗，
pack 是为了减少空间占用，压缩二进制文件显然达不到这个目的。

7. SQL注入技术分类,以及每一种注入技术的作用
<br>&emsp;&emsp;基于时间的注入(time-based injection):
<br>&emsp;&emsp;参考网址:[User-Agent注入攻击和基于时间的注入](www.freebuf.com/articles/web/105124.html)
<br>&emsp;&emsp;作用:用于猜测数据库名、表名、字段名、数据信息等等
<br>&emsp;&emsp;基于错误的注入(error-based injection):
<br>&emsp;&emsp;参考网址:[基于错误回显的SQL注入整理](http://www.51testing.com/html/26/n-3364326.html)
<br>&emsp;&emsp;作用:用于爆出数据库名、表名、字段名、数据信息等等
<br>&emsp;&emsp;基于bool的注入(boolean-based injection):
<br>&emsp;&emsp;参考网址:
<br>&emsp;&emsp;作用:
<br>&emsp;&emsp;基于union的注入(union-based injection):
<br>&emsp;&emsp;参考网址:
<br>&emsp;&emsp;作用:进行拖数据操作

8. SQL注入的目的: 提权和获取数据


9. MySQL三种报错模式注入利用floor、Extractvalue、UpdateXml、name_const()函数利用
[基于错误的注入利用](http://www.gx0759.com/241.html)
[基于错误的注入name_const()函数利用](http://www.dreaminto.com/2013/0620/753.html)
extractvalue()(有长度限制)
**extractvalue(xml_document,xpath_string)**;(文件名有长度限制,最长32位)
第一个参数:xml_document是string格式,为xml文档对象的名称
第二个参数:xpath_string（xpath格式的字符串)）
作用:从目标xml中返回包含所有查询值的字符串
**updatexml(xml_document,xpath_string,new_value)**;
第一个参数:xml_document是string格式,为xml文档对象的名称
第二个参数:xpath_string(xpath格式的字符串)
第三个参数:new_value,string格式,替换查找到符合条件的数据
作用:改变文档中符合条件的节点的值
updatexml()(有长度约束)
exp()函数
10. tamper目录讲解

|脚本名称	|作用|
|-----|-----|
|apostrophemask.py	|用utf8代替引号|
|equaltolike.py	|like 代替等号|
|space2dash.py	|绕过过滤‘=’ 替换空格字符（”），（'' – '）后跟一个破折号注释，一个随机字符串和一个新行（’ n’）|
|greatest.py	|绕过过滤’>’ ,用GREATEST替换大于号。|
|space2hash.py	|空格替换为#号 随机字符串 以及换行符|
|apostrophenullencode.py	|绕过过滤双引号，替换字符和双引号。|
|halfversionedmorekeywords.py	|当数据库为mysql时绕过防火墙，每个关键字之前添加mysql版本评论|
|space2morehash.py	|空格替换为 #号 以及更多随机字符串 换行符|
|appendnullbyte.py	|在有效负荷结束位置加载零字节字符编码|
|ifnull2ifisnull.py	|绕过对 IFNULL 过滤。 替换类似’IFNULL(A, B)’为’IF(ISNULL(A), B, A)’|
|space2mssqlblank.py|	空格替换为其它空符号|
|base64encode.py	|用base64编码替换|
|space2mssqlhash.py	|替换空格|
|modsecurityversioned.py	|过滤空格，包含完整的查询版本注释|
|space2mysqlblank.py	|空格替换其它空白符号(mysql)|
|between.py	|用between替换大于号（>）|
|space2mysqldash.py	|替换空格字符（”）（’ – ‘）后跟一个破折号注释一个新行（’ n’）|
|multiplespaces.py	|围绕SQL关键字添加多个空格|
|space2plus.py	|用+替换空格|
|bluecoat.py	|代替空格字符后与一个有效的随机空白字符的SQL语句。 然后替换=为like|
|nonrecursivereplacement.py	|取代predefined SQL关键字with表示 suitable for替代（例如 .replace（“SELECT”、””)） filters|
|space2randomblank.py	|代替空格字符（“”）从一个随机的空白字符可选字符的有效集|
|sp_password.py	|追加sp_password’从DBMS日志的自动模糊处理的有效载荷的末尾|
|chardoubleencode.py	|双url编码(不处理以编码的)|
|unionalltounion.py	|替换UNION ALL SELECT UNION SELECT|
|charencode.py	|url编码|
|randomcase.py	|随机大小写|
|unmagicquotes.py	|宽字符绕过 GPC addslashes|
|randomcomments.py	|用\/\*\*\/分割sql关键字|
|charunicodeencode.py	|字符串 unicode 编码|
|securesphere.py	|追加特制的字符串|
|versionedmorekeywords.py	|注释绕过|
|space2comment.py	|Replaces space character (‘ ‘) with comments ‘/**/’|

11. 网络安全方面的网站
 <br>&emsp;&emsp;10.01 [freebuf](www.freebuf.com)
 <br>&emsp;&emsp;10.02 [乌云网](www.wooyun.org)
 <br>&emsp;&emsp;10.03 [乌云网知识库](drops.wooyun.org)
 <br>&emsp;&emsp;10.04 www.shack2.org
 <br>&emsp;&emsp;10.05 www.shack2.org/article/142279387.html
 <br>&emsp;&emsp;10.06 [防止sql注入和sqlmap介绍](http://lawson.cnblogs.com/)
 <br>&emsp;&emsp;10.07 [Beyond SQLi: Obfuscate and Bypass](https://www.exploit-db.com/papers/17934/)
 <br>&emsp;&emsp;10.08 [waf 绕过的技巧](http://drops.wooyun.org/tips/132)
 <br>&emsp;&emsp;10.09 [MySql注入科普](http://drops.wooyun.org/tips/123)
 <br>&emsp;&emsp;10.10 [深入了解SQL注入绕过waf和过滤机制](http://drops.wooyun.org/tips/968)
 <br>&emsp;&emsp;10.11 [MySQL暴错注入方法整理](http://www.waitalone.cn/mysql-error-based-injection.html)
 <br>&emsp;&emsp;10.12 [mysql ,floor,ExtractValue,UpdateXml三种报错模式注入利用方法](http://www.dreaminto.com/2013/0620/753.html)
 <br>&emsp;&emsp;10.13 [利用Insert、Update、Delete注入获取数据](http://drops.wooyun.org/tips/2078)
 <br>&emsp;&emsp;10.14 [BigInt Overflow Error-based sql injection](https://osandamalith.wordpress.com/2015/07/08/bigint-overflow-error-based-sql-injection/)
 <br>&emsp;&emsp;10.15 [基于BIGINT溢出错误的SQL注入](http://drops.wooyun.org/web/8024)
 <br>&emsp;&emsp;10.16 [使用exp进行SQL报错注入](http://drops.wooyun.org/tips/8166)


