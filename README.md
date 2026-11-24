# biofake

Windows 虚拟生物识别硬件（虚拟指纹传感器）——通过一个用户态驱动（UMDF 2.x / WBDI）让 Windows 把纯软件设备当作真实的指纹传感器，并可通过配套控制软件按需注入伪造的指纹数据。

> 仅用于安全研究 / 驱动开发测试。请在自己的机器上使用。

## 架构

```
应用(WinBio API) → WbioSrvc → 内置 SensorAdapter → biofake.sys(UMDF2, WBDI) ←控制通道← biofakectl.exe
                                  ↓ BIR
                             BioFakeEngineAdapter（哈希匹配）→ 内置 StorageAdapter → WinBioDatabase
```

- **驱动**：Root\BioFake 暴露 GUID_DEVINTERFACE_BIOMETRIC_READER，实现全部必备 WBDI IOCTL；Root\BioFakeCtl 暴露控制接口（添加/选择/注入密钥）。
- **密钥**：每个 key = 名称 + 32 字节种子，驱动据此确定性生成 ANSI-381 格式伪指纹图像；同一 key 采集结果逐字节一致，因此可完成 Windows Hello 的注册与匹配。
- **模式**：ready（自动用当前 key 应答采集）/ reject / failure / custom（注入任意 BIR）/ 无 key 时挂起等待 present。

## 构建

GitHub Actions 已配置（.github/workflows/build.yml，windows-latest + WDK NuGet + Inf2Cat + 测试签名），产物在 Actions Artifacts。

本地：VS2022 + WDK，`msbuild biofake.sln /p:Configuration=Release /p:Platform=x64`。

## 安装（测试签名模式）

```powershell
# 管理员 PowerShell，在发布包目录
bcdedit /set testsigning on          # 需重启
Import-Certificate .\biofake-test.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate .\biofake-test.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
pnputil /add-driver biofake_wudf.inf /install
.\biofakectl.exe install .\biofake_wudf.inf   # 创建 Root\BioFake / Root\BioFakeCtl 设备节点
.\biofakectl.exe test                          # WinBio 枚举验证
```

## 使用

```text
biofakectl keys                    列出密钥
biofakectl create <名字>           创建密钥（随机种子）
biofakectl select <名字>           设为活动密钥（后续采集都返回它）
biofakectl present <名字>          手动应答一次挂起的采集
biofakectl mode ready|reject|failure|custom
biofakectl payload <file.bir>      注入自定义 BIR 数据
biofakectl status | test | console | hotkeys | install | uninstall
```

验证设备识别：设备管理器出现“BioFake Virtual Fingerprint Sensor”；`biofakectl test` 能枚举出 WinBio 单元；Settings → 登录选项出现指纹选项。注意：Windows Hello 真实登录要求引擎适配器具备微软 WindowsHello 签名（见 windows-hello-driver-signing），本项目默认输出为测试签名，因此设备识别与 WinBio 注册/验证可用，Hello 登录环节可能被拒绝——这正是“识别成功”与“通过认证”的边界。

## 为什么不用 USB/IP

USB/IP 只是把真实 USB 设备转发到 Windows，虚拟指纹设备没有对应的真实 USB 硬件/描述符，仍需在 Windows 侧配套 WBDI 驱动才能被 WBF 识别，收益为零；直接实现根枚举 WBDI 驱动更简单可控。

## 目录

```
driver/    UMDF2 WBDI 驱动 (driver.c, INF, vcxproj)
engine/    WinBio Engine Adapter (SHA256 匹配)
ctl/       biofakectl.exe 控制工具
shared/    驱动/工具共用 IOCTL 定义
scripts/   install.ps1 / package.ps1
.github/   Actions workflow
```
