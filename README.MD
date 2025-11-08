# 在 ZMap 源码中集成 SCTP 探测模块

## 1. 克隆 ZMap 源码
从 GitHub 克隆 ZMap 官方源码。

## 2. 复制探测模块代码
将本项目 `src/probe_modules` 目录中的[module_sctp.c ](src/probe_modules/module_sctp.c), [text](src/probe_modules/module_sctp.h)复制到 ZMap 源码对应目录：
```
zmap/src/probe_modules/
```

## 3. 修改 CMake 构建配置
编辑 ZMap 的构建配置文件 `zmap/src/CMakeLists.txt`，在变量 `PROBE_MODULE_SOURCES` 中添加模块文件：
```cmake
${CMAKE_CURRENT_SOURCE_DIR}/probe_modules/module_sctp.c
```

## 4. 注册模块常量
编辑 `zmap/src/probe_modules/probe_modules.c`，在模块注册表中添加与 `module_sctp.c` 对应的常量定义：

**模块声明区：**
```c
extern probe_module_t module_sctp;
```

**模块列表：**
```c
&module_sctp,
```

## 5. 修改接收处理代码
在 `zmap/src/recv.c` 文件中，找到以下代码段：
```c
} else if (ip_hdr->ip_p == IPPROTO_UDP) {
	struct udphdr *udp = get_udp_header(ip_hdr, len_ip_and_payload);
	if (udp) {
		src_port = udp->uh_sport;
	}
```

在其后添加以下代码：
```c
} else if (ip_hdr->ip_p == IPPROTO_SCTP) {
	if (len_ip_and_payload >= (ip_hdr->ip_hl * 4 + sizeof(struct sctp_header))) {
		struct sctp_header *sctp = (struct sctp_header *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
		src_port = sctp->src_port;
	}
```