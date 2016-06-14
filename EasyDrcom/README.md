#EasyDrcom
##Current Version: v0.8


###License
---
    Copyright (C) 2014 Shindo
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
        
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

###What's EasyDrcom?
---
**EasyDrcom** 是 **_Shindo_** 编写的为哈尔滨工业大学（威海）量身定制的**第三方Dr.COM客户端**，可在教学区、家属区、学生区使用，可运行于_Windows, Mac OS X, Linux_（包括_OpenWrt_）。 

**EasyDrcom** 将校园网转换为无线信号，从此手机、平板上校园网无需使用学校提供的客户端、无需打开电脑共享Wifi。

有关如何使用 **EasyDrcom**, 请访问 http://bbs.ghtt.net/thread-1984091-1-1.html

此外，EasyDrcom已推出GUI版，详情请访问：http://bbs.ghtt.net/thread-2013765-1-1.html

###Other projects
---
如果需要Python版本（支持d, p, x三版），请参考：https://github.com/drcoms/drcom-generic

此外，这里还有一个增加了802.1X心跳包的版本：https://github.com/sunke-github/Drcom8021x_Openwrt

###Compile Tips
---
####下面以向Linux平台编译为例。

编译 **EasyDrcom** 是十分简单的：

    g++ -DLINUX -Os -s -std=c++0x -o EasyDrcom md5.c main.cpp -lpcap -lpthread
    
你或许已经发现了，**EasyDrcom** 依赖于：
    
    libpcap (1.5.3)
    boost (1.55.0)

_括号里标注的是作者使用的版本_

请注意，如果向OpenWrt编译的话，请再加上编译参数，并且把他放在-DLINUX前面：
    
    -D OPENWRT
    
这样的话，整体看起来像这样：

    g++ -DOPENWRT -DLINUX -Os -s -std=c++0x -o EasyDrcom md5.c main.cpp -lpcap -lpthread

###Special Thanks
---
**EasyDrcom** 的诞生离不开无数前辈的努力，下面列出的是参照的项目：

* jdrcom (@Google Code: http://code.google.com/p/jdrcom/)

同时，也离不开许多同学的测试，这里不再一一列举。