# Copilot for IDA Pro

### [English](readme.md) | 中文

👋 欢迎使用IDA Pro的ChatGPT插件，在这里，OpenAI的GPT模型的前沿能力与IDA Pro的强大反汇编和调试功能相结合。这个插件利用LangChain和最新的基于Agent的方法自动化分析IDA中的反编译代码，使逆向工程变得前所未有地简单和互动。

![预览](https://github.com/Antelcat/ida_copilot/blob/main/img/Preview.gif?raw=true)

## 功能特点

- 🤖 **自动代码分析**：只需导航到一个函数，启动插件，Copilot就会自动分析。
- 🔍 **上下文功能信息**：获取关于函数的详细信息，包括定义、伪代码和相关注释。
- ✏️ **函数重命名**：AI将自动分析该函数并根据其功能对其重命名。
- 🛠️ **无缝集成**：插件与IDA Pro无缝集成，为快速访问添加菜单操作并为高级用户提供键盘快捷方式。
- ⏫ **持续改进**：新功能和新能力正在紧张开发中。

## 入门

### 先决条件

- 带有Hex-Rays Decompiler的IDA Pro
- 配置了IDA Pro的Python环境
- 一个OpenAI API密钥，它应该以`sk-`开头。如果您还没有，可以在[这里](https://platform.openai.com/account/api-keys)创建一个。

### 安装

1. 克隆存储库或下载项目的源代码zip包。
2. 使用`pip install -r requirements.txt`安装所需的依赖项。
3. 将`ida_copilot`文件夹和`ida_copilot.py`文件复制到IDA Pro的插件目录中，类似于`C:\Program Files\IDA Pro 7.5\plugins`。
4. 在环境变量`OPENAI_API_KEY`中设置您的OpenAI API密钥。

### 使用

- 启动IDA Pro并加载一个二进制文件。
- 导航到您希望分析的函数。
- 点击`编辑 > Copilot`或使用快捷键`Ctrl+Shift+P`运行ChatGPT分析。
- 等待分析完成并显示结果。

## 工作原理

这个插件的核心是基于一个创新的"Agent"框架，ChatGPT在此系统中充当**大脑**。将ChatGPT想象为一个精明的合作伙伴，它能够辨别出IDA环境中接下来需要做什么。这个由AI驱动的代理根据当前的上下文及其对代码的理解，不断地做出下一步行动的决策。

通过插件提供的一系列Python API，ChatGPT与IDA Pro无缝交互。它利用这些接口来分析函数，重命名变量，生成漏洞利用代码，甚至就像一个人类专家一样与您进行交互式会话。这种持续的分析、决策和互动循环，使这个插件不仅仅是一个工具，而是您逆向工程挑战中的智能伴侣。

## 开发

这个插件正在积极开发中，定期添加新功能。如果您想贡献或有建议，请随时在GitHub上开issue或pr。

### 开发中的功能
- ✍️ **局部变量重命名**：AI将自动分析函数并根据其功能重命名局部变量。
- 🎯 **漏洞利用生成**：AI将自动分析函数并为其生成漏洞利用代码。
- 💬 **交互式Copilot**：以对话方式与插件互动，对您正在处理的代码提问或获取澄清。

## 许可证

该项目使用[MIT许可证](LICENSE)。

## 致谢

- 该项目使用了OpenAI的GPT技术。
- 该项目利用了LangChain库。
- 感谢IDA Pro社区的持续支持和反馈。

我们希望这个插件能够帮助您利用AI的力量将您的逆向工程任务提升到一个新的水平！