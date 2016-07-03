1. google dork
2. [认识SQL注入的类型](http://www.codesec.net/view/211276.html)
3. BISECTION METHOD
4. http://del.icio.us/inquis/sqlinjection Links 1 through 10 of 222 by Bernardo Damele A. G. tagged sqlinjection
5. 项目框架结构
    doc:        项目的一些说明文档,主要包括作者信息、修改日志、版权申明、常见问题、用户手册等等
    extra:      项目所需的额外文件
    lib:        项目核心实现文件夹
    plugins:    项目的插件,主要包括连接数据库、枚举数据库信息,接管数据库
    procs:      项目所需要使用的存储过程
    shell:      项目shell相关的信息
    tamper:     项目进行注入的时候,绕过防火墙的一些基本伪装
    thirdparty: 项目的第三方库文件,主要包括后台颜色输出控制
    txt:        项目进行暴力破解所需要的文件,主要包括常见列名、常见表名、常见的输出、用户代理、密码字典等等
    udf:        项目的用户自定义功能函数,主要用于在后台数据库系统中执行
    waf:        项目目前能够是别的防火墙种类型信息
    xml:        项目进行注入需要使用的信息,主要包括注入的payload、边界选择条件、数据库识别的报错信息、查询数据库使用的信息
    .gitattributes 版本控制相关的信息
    .gitgnore      版本控制时,进行忽略的信息
    .travis.yml:   项目版本信息
    readme.md:  项目的用户手册
    sqlmap.conf:   项目的默认配置信息
    sqlmap.py      项目测试入口
    sqlmapapi.py   项目测试入口

git 创建 .gitignore 文件 建立项目过滤规则

6. [ .gitignore](http://blog.csdn.net/liuqiaoyu080512/article/details/8648266)
Git 可以管理所有文件的变更， 但并不是所有文件都有意义。
    6.1. 大部分二进制文件没有意义
　　      比如说 VC 工程的 Debug 和 Release 文件夹下的文件， 或者 Java 项目的 bin 文件夹中的 class 文件， 
         这些文件都是基于源代码生成的， 只要有源代码就能生成出来，所以版本管理的时候应该忽略它们。
    6.2. 有些文本文件也没有意义
　　      比如说 VC 工程中的 .plg 文件， 它是个 html 格式的文本文件， 保存了编译后产生的 error 和 warning， 显然没有进行版本管理的必要。
    6.3. 有些二进制文件不能忽略
　　      比如说 MFC 工程的 res\Toolbar.bmp， 是工具栏的位图文件，二进制文件， 如果忽略，工程就不完整了，别人 clone 你的版本库后用不了。 而这些文件一般不频繁变更，进行版本管理也不浪费空间。
　　      总之，能从别的文件生成的文件就应该被忽略。 要忽略这些文件，一般在 .gitignore 中设置规则， 如下是一篇对 .gitignore 介绍得很好的文章

7. [浅识 .gitattributes](https://www.jmlog.com/recognize-gitattributes/)
.gitattributes 位于 Git 仓库的根目录下，用于对特定文件的属性进行设定。
* text=auto
默认设置所有文件是文本类型时，Checkout 时换行符转换为 Unix 换行符 LF，不是文本类型时，不作改变。
.vimrc text eol=lf
.gvimrc text eol=lf
*.vim text eol=lf
强制将 Vim 的配置文件的换行符转换为 Unix 换行符 LF。
*.rb diff=ruby
*.tex diff=tex
根据不同类型指定不同的 diff 模式，diff 时更美观。
*.png binary -delta
*.jpeg binary -delta
*.jpg binary -delta
*.gif binary -delta
*.gz binary -delta
*.bz2 binary -delta
*.tgz binary -delta
对于二进制文件，指定 binary 属性，等价于 -text -diff，含义不言而喻。
-delta 让 Git 在 pack 时不进行压缩，减少 git commit 等操作时的系统时间消耗，
pack 是为了减少空间占用，压缩二进制文件显然达不到这个目的。


