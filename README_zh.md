# MobSF 中文本地化

本分支 (`chinese-localization`) 对 MobSF 进行了全面的中文本地化改造，支持**中文界面**和**中文报告输出**。

## 改造内容

### 1. Django i18n 基础设施
- 在 `settings.py` 中添加 `LocaleMiddleware`，设置默认语言为 `zh-hans`（简体中文）
- 配置 `LANGUAGES` 支持简体中文和英文切换
- 添加 `LOCALE_PATHS` 配置
- 添加 i18n context processor 和自定义语言上下文处理器
- 新增 `/i18n/setlang/` 路由支持语言切换

### 2. Web 界面中文化
所有 HTML 模板已翻译为中文，包括：
- **导航栏**：最近扫描、静态分析、动态分析、API、捐赠、文档、关于
- **首页**：上传并分析、拖拽上传、下载并扫描安装包
- **扫描记录**：扫描列表、操作按钮（静态报告、动态报告、安全评分卡、删除扫描等）
- **扫描队列**：任务列表、状态监控
- **认证页面**：登录、注册、修改密码、用户管理
- **静态分析**：Android/iOS/Windows 分析结果页面、安全评分卡、应用对比
- **动态分析**：Android/iOS 动态分析器、动态报告、API 监控、日志查看
- **其他页面**：关于、捐赠、错误页、ZIP 说明等

### 3. PDF 报告中文化
- Android/iOS/Windows 三种 PDF 报告模板全部翻译
- 添加 CJK 字体回退支持（PingFang SC、Microsoft YaHei、Noto Sans CJK SC 等）
- 确保报告中的中文在 wkhtmltopdf 渲染时正确显示

### 4. 安全规则中文化
所有 YAML 规则文件中的 `message` 字段已翻译：
- `android_rules.yaml` - Android 安全规则（52条）
- `android_apis.yaml` - Android API 规则（54条）
- `android_permissions.yaml` - Android 权限规则
- `android_niap.yaml` - NIAP 规则
- `swift_rules.yaml` - Swift 安全规则（39条）
- `objective_c_rules.yaml` - Objective-C 安全规则（25条）
- `ios_apis.yaml` - iOS API 规则（13条）
- `behaviour_rules.yaml` - 行为分析规则（211条）

### 5. Python 错误消息中文化
关键 Python 视图中的用户可见错误消息已翻译：
- 首页视图 (`home.py`)
- PDF 生成 (`pdf.py`)
- 共享功能 (`shared_func.py`)
- AppSec 仪表板 (`appsec.py`)
- 工具函数 (`utils.py`)

## 语言切换

默认语言为简体中文。如需切换为英文，访问：
```
/i18n/setlang/?lang=en-us
```

切回中文：
```
/i18n/setlang/?lang=zh-hans
```

## 字体支持

PDF 报告生成时，wkhtmltopdf 需要系统安装中文字体。已配置 CSS 字体回退链：
- macOS: PingFang SC（系统自带）
- Linux: Noto Sans CJK SC / WenQuanYi Micro Hei（需安装）
- Windows: SimHei / Microsoft YaHei（系统自带）

Linux 安装中文字体：
```bash
# Ubuntu/Debian
sudo apt-get install fonts-noto-cjk

# 或
sudo apt-get install fonts-wqy-microhei
```

## 文件变更清单

### 新增文件
- `mobsf/MobSF/views/i18n.py` - 语言切换视图和上下文处理器
- `mobsf/locale/` - Django locale 目录

### 修改文件
- `mobsf/MobSF/settings.py` - i18n 配置
- `mobsf/MobSF/urls.py` - 语言切换路由
- `mobsf/templates/base/nav.html` - 导航栏
- `mobsf/templates/base/base_layout.html` - 基础布局
- `mobsf/templates/general/home.html` - 首页
- `mobsf/templates/general/recent.html` - 最近扫描
- `mobsf/templates/general/tasks.html` - 扫描队列
- `mobsf/templates/general/about.html` - 关于
- `mobsf/templates/general/dynamic.html` - 动态分析入口
- `mobsf/templates/general/error.html` - 错误页
- `mobsf/templates/general/zip.html` - ZIP 说明
- `mobsf/templates/general/donate.html` - 捐赠
- `mobsf/templates/auth/*.html` - 认证页面（登录、注册、修改密码、用户管理）
- `mobsf/templates/pdf/android_report.html` - Android PDF 报告
- `mobsf/templates/pdf/ios_report.html` - iOS PDF 报告
- `mobsf/templates/pdf/windows_report.html` - Windows PDF 报告
- `mobsf/templates/static_analysis/*.html` - 静态分析模板
- `mobsf/templates/dynamic_analysis/**/*.html` - 动态分析模板
- `mobsf/templates/404.html`, `403.html`, `500.html` - 错误页面
- `mobsf/StaticAnalyzer/views/android/rules/*.yaml` - Android 规则
- `mobsf/StaticAnalyzer/views/ios/rules/*.yaml` - iOS 规则
- `mobsf/MalwareAnalyzer/views/android/rules/behaviour_rules.yaml` - 行为规则
- `mobsf/MobSF/views/home.py` - 首页视图
- `mobsf/StaticAnalyzer/views/common/pdf.py` - PDF 生成
- `mobsf/StaticAnalyzer/views/common/shared_func.py` - 共享功能

## 保持同步

本分支基于 MobSF master 分支创建。如需同步上游更新：
```bash
git remote add upstream https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
git fetch upstream
git merge upstream/master
```

## 许可证

与 MobSF 保持一致，遵循相同的开源许可证。
