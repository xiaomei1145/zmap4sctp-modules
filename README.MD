在 ZMap 源码中集成本项目的 SCTP

1. 克隆 ZMap 源码
GitHub 克隆 ZMap 的官方源码

2. 复制探测模块代码
本项目目录下的
src/probe_modules/
中的所有文件，复制到 ZMap 源码对应的目录：
zmap/src/probe_modules/

3. 修改 CMake 构建配置
ZMap 的构建配置文件：
zmap/src/CMakeLists.txt
在变量 PROBE_MODULE_SOURCES 中，添加模块文件：
${CMAKE_CURRENT_SOURCE_DIR}/probe_modules/module_sctp.c

4.注册模块常量
zmap/src/probe_modules/probe_modules.c
在模块注册表中添加与 module_sctp.c 对应的常量定义

模块声明区
extern probe_module_t module_sctp;

模块列表
&module_sctp,
