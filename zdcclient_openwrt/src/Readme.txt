###############################################################################################
源码来自Pentie，只是做适当修改使之能在路由器中运行
相关链接
https://code.google.com/p/zdcclient/
https://github.com/isombyt/zdcclient

所需工具及库
[libpcap](http://www.tcpdump.org/release/)
推荐1.0版本，编译出来的libpcap.a较小，路由器本身资源比较紧张
toolchain用的是dd-wrt的，openwrt提供的编译libpcap时有点问题
http://www.dd-wrt.com/dd-wrtv2/downloads/others/sourcecode/toolchains/current-toolchains.tar.bz2
貌似有900+MB，速度又慢
推荐toolchains.x86.debian.sp1.tar.bz2，只有70多M这个官网已经没有了，某离线下载还可以下得到http://kuai.xunlei.com/d/44-SAwJkugBouOpQdae
或者自行google吧
libiconv这个是可选的，如不需要服务器回传的信息可以不用加入

解压工具链，把工具链的bin目录加入PATH
cd 到libpcap目录
export ac_cv_linux_vers=2.4
./configure --host=mips-linux --with-pcap=linux --prefix=~/toolchains/3.4.6-uclibc-0.9.28(你的工具链所在路径)
make
make install

编译路由器用的zdclient，根据实际情况适当修改下源码，主要是Makefile的libpcap.a的路径，已经zdclient.c的认证服务器的MAC地址
clone zdcclient4mips
git clone git://github.com/zetong/zdcclient4mips.git
cd zdcclient4mips
make

根据实际情况修改runzdclient
然后把与zdclient zdclient传送到路由器中
openwrt可以用scp
dd-wrt与tt有两种方案
1.固件需要支持jffs的，开启后可用scp或ftp传送到路由器中
2.修改路由器固件，把上面说道的两个文件cp到/usr/bin或/bin中，其他也可以，不过最好是PATH内的，方便执行
推荐第二种,不过个人还是更倾向与openwrt，相比另外两个定制性强太多了


如果你是佛山科学技术学院本部的同学，应该不需要修改，直接make了，已经成功在路由器中运行，低调使用就行。




#######################################################################################################
ZDClient v1.2 Readme

安装：
    在安装前，请用户先编辑运行脚本文件runzdclient，将其中的user和pass分别修改成您的帐号和密码并保存。 

    安装需要root权限，这通常使用sudo或者su -c

    sudo ./install 

    安装程序会复制核心程序zdclient以及用户脚本runzdclient到系统目录/usr/bin，并设置相关属性，如果用户希望安装到其他目录，可给出目的路径，如sudo ./install /usr/local/bin，但请保证目的目录在系统PATH环境变量内。 

    成功执行安装将看到####Installation Done.####的提示。 

运行：
	
    如果用户配置的帐号信息无误并且安装成功，那么用户只需要运行runzdclient，即可看到有关的认证成功的信息。 

    如果系统内安装有libnotify的工具，运行脚本时会出现如图的提示(Ubuntu中的效果，如果没有，请安装sudo apt-get libnotify-bin):[没有安装libnotify-bin虽然不能显示，但并不影响认证。]

    可以通过桌面的启动器运行runzdclient，或把把runzdclient加入到比如GNOME的“系统->首选项->启动程序“当中，以便每次登录系统即可自动认证上网。 

终止：
    用户执行一次`runzdclient -l`，即可成功离线。 

编译：
    用户可通过git获得最新的开发代码：

    git clone http://github.com/isombyt/zdcclient.git  

    编译需要libpcap库，一般Linux发行版里面安装libpcap包即可，在ubuntu中，需要libpcap-dev：

        sudo apt-get install libpcap-dev

    从命令行进入源代码目录，运行make，应该很快就能生成zdclient，当然前提是系统中安装了gcc等编译环境，这里不再累赘。 

    make install也可完成安装，这根运行install效果基本一样，同样有make uninstall以供卸载。再次提醒安装前先修改runzdclient文件内的账户信息。 

    MacOS / BSD 用户编译：

    Mac用户首先要安装gcc，需要从http://connect.apple.com/下载安装Xcode Tools，具体请查阅Apple Dev的信息。然后下载libpcap的源代码，http://www.tcpdump.org/release/libpcap-1.0.0.tar.gz，解压后分别运行
    ./configure
    make 
    sudo make install

    最后在本程序的源代码目录运行

    make -f Makefile.bsd

    即可生成可运行程序。安装运行参考上文Linux部分。

其他

    当用户使用的认证网卡不是默认的第一个网卡（如eth0）时，可使用runzdclient --dev eth1这样的参数方式启动程序，或者修改runzdclient文件内ARGS=""，加入自定义的参数。 

DHCP模式：
    
    当认证环境需要使用DHCP模式时，需要使用--dhcp参数启动(可在runzdclient的#其他参数行设定)
    
	这里提到的DHCP模式不是完全指网卡是否用DHCP获取IP，DHCP模式的特点是：
	1.在Windows启动后，提示本地连接受限，网卡IP为169.254.x.x的格式，使用客户端认证后才重新获取IP；
	2.在Linux下启动后，网卡IP为空；
	如果符合以上两点，则必须使用--dhcp模式启动zdclient，而且在认证成功后，是需要运行系统的DHCP客户端重新获取一次IP的，通常是dhclient，这一点在启动脚本dhcp_zdc_run.sh内已经包含。
	
	至于在认证前已经能获得IP的环境，不是这里所说的动态模式，使用静态模式启动即可。

版本号：
	认证报文中包含了协议版本号，zdclient 0.4版中的默认版本号是以武汉大学官方客户端的3.5.04.1013fk为准，已知更新的版本是3.5.04.1110fk，不过暂时不影响使用。如果您使用时发现提示&&Info: Invalid Username or Client info mismatch.，很可能是软件的版本号和您使用环境的认证系统不匹配，可尝试使用--ver参数自定义版本号，或联系作者PT，帮助ZDClient兼容您的环境。
	
	

A PT Work. 

原项目主页： http://code.google.com/p/zdcclient/
Blog:    http://apt-blog.co.cc
GMail:   pentie@gmail.com

