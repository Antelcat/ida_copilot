# Copilot for IDA Pro

### English | [中文](readme_cn.md)

👋 Welcome to the ChatGPT plugin for IDA Pro, where the cutting-edge capabilities of OpenAI's GPT models meet the powerful disassembly and debugging features of IDA Pro. This plugin leverages LangChain and the latest Agent-based approach to automate the analysis of decompiled code in IDA, making reverse engineering easier and more interactive than ever.

![Preview](https://github.com/Antelcat/ida_copilot/blob/main/img/Preview.gif?raw=true)

## Features

- 🤖 **Automatic Code Analysis**: Simply navigate to a function, run the plugin, and Copilot will automatically analyze it.
- 🔍 **Contextual Function Information**: Get detailed information about functions, including definitions, pseudocode, and relevant comments.
- ✏️ **Rename Functions**: AI will automatically analyze the function and rename it based on its functionality.
- 🛠️ **Seamless Integration**: The plugin integrates smoothly with IDA Pro, adding menu actions for quick access and keyboard shortcuts for users.
- ⏫ **Continuous Improvement**: Ongoing development promises the addition of new features and capabilities.

## Getting Started

### Prerequisites

- IDA Pro with Hex-Rays Decompiler
- Python >= 3.9 environment configured with IDAPython
- An OpenAI API key, which should start with `sk-`. You can create one [here](https://platform.openai.com/account/api-keys) if you don't have one already.

### Installation

1. Clone the repository or download the source code zip package.
2. Install required dependencies using `pip install -r requirements.txt`.
3. Copy `ida_copilot` folder and `ida_copilot.py` file to the plugins directory of IDA Pro, similar to `C:\Program Files\IDA Pro 7.5\plugins`.
4. Set up your OpenAI API key in the environment variable `OPENAI_API_KEY`.

### Usage

- Launch IDA Pro and load a binary file.
- Navigate to a function you wish to analyze.
- Click `Edit > Copilot` or Use the shortcut `Ctrl+Shift+P` to run the ChatGPT analysis.
- Wait for the analysis to complete and the results to be displayed.

## How It Works

The core of this plugin operates on the innovative concept of an "Agent" framework, with ChatGPT serving as the **Brain** of this system. Imagine ChatGPT as an astute collaborator that discerns what needs to be done next within the IDA environment. This AI-driven agent continually makes decisions on the next course of action based on the current context and its understanding of the code.

Through an array of Python APIs provided by the plugin, ChatGPT seamlessly interacts with IDA Pro. It harnesses these interfaces to analyze functions, rename variables, generate exploits, and even hold an interactive session with you, just like a human expert would. This continuous loop of analysis, decision-making, and interaction is what makes this plugin not just a tool, but a smart companion for your reverse-engineering challenges.

## Development

This plugin is under active development, with new features being added regularly. If you wish to contribute or have suggestions, please feel free to open an issue or a pull request on GitHub.

### Features in Development
- ✍️ **Rename Local Variables**: AI will automatically analyze the function and rename local variables based on their functionality.
- 🎯 **Exploit Generation**: AI will automatically analyze the function and generate an exploit for it.
- 💬 **Interactive Copilot**: Engage with the plugin in a conversational manner to ask questions or get clarifications about the code you're working on.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

- This project utilizes OpenAI's GPT technology.
- This project utilizes the LangChain library.
- Thanks to the IDA Pro community for their continuous support and feedback.

We hope this plugin empowers you to take your reverse engineering tasks to the next level with the power of AI!

