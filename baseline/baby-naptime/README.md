<p align="center">
  <img src="demo/logo.png" width="500">
</p>

# 🍼 Baby Naptime

> *Find vulnerabilities while you sleep!*

A very simple and basic open source implementation inspired by [Google's Project Naptime](https://googleprojectzero.blogspot.com/2024/06/project-naptime.html) - a vulnerability analysis tool that uses Large Language Models (LLMs) to discover and exploit native vulnerabilities. This was a weekend project, so please expect some hacky stuff here and there.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)
![Ubuntu Only](https://img.shields.io/badge/platform-ubuntu-orange)
![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-red)

![Demo](demo/demo.gif)


## 🔍 Overview

Baby Naptime leverages the intelligence of LLMs to revolutionize security analysis:

- **Smart vulnerability detection** that understands code context
- **Automated exploit generation** to prove concepts
- **Memory corruption analysis** that catches what static analyzers miss
- **Integrated debugging** with security-focused insights

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🧠 **Intelligent Analysis** | Uses LLMs to understand code semantics and identify potential vulnerabilities |
| 🛠️ **Automated Exploitation** | Generates and tests exploit payloads with minimal user intervention |
| 💾 **Memory Analysis** | Deep inspection of memory layouts and corruption patterns |
| 🔬 **Advanced Debugging** | GDB integration with security-focused analysis capabilities |
| 🧭 **Code Navigation** | Smart traversal of codebases to focus on vulnerability-prone areas |
| 📝 **Reporting** | Detailed vulnerability reports with exploitation paths and remediation suggestions |
| 📊 **Conversation Summarization** | Smart management of context history to maintain analysis quality |
| 🔄 **Adaptive Binary Compilation** | Automatically compiles targets with security mitigations disabled for testing |

## 📋 Requirements

- Python 3.7 or higher
- GDB debugger
- C/C++ compiler (g++)
- OpenAI API key
- Required Python packages (see `requirements.txt`)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/baby-naptime.git
cd baby-naptime

# Install dependencies
pip install -r requirements.txt

# Set up your API key (supports OpenAI)
export OPENAI_API_KEY='your-openai-key-here'

# Install required system dependencies
sudo apt-get install gdb g++ colorama
```

### Usage

Basic command:

```bash
python run.py -c <code_file> [options]
```

#### Command Options

```
-c, --code_file        Path to the source code file to analyze (required)
-d, --code-directory   Directory containing additional source files (default: ".")
-m, --max-iterations   Maximum number of analysis iterations (default: 100)
-l, --llm-model        LLM model to use (choices: gpt-3.5-turbo, gpt-4o, gpt-4o-mini, o3-mini, o1-preview)
-f, --main-function    Entry function to begin analysis (default: "main")
-k, --keep-history     Number of conversation history items to keep (default: 14)
```

### Example

```bash
# Analyze a C++ file using Openai's o3-mini model
python run.py -c code/test.cpp -l o3-mini -k 15
```

This command will:
1. Load and parse `test.cpp` 
2. Compile the code with security mitigations disabled (`-fno-stack-protector -z execstack -no-pie`)
3. Use the o3-mini model for vulnerability analysis
4. Maintain a context history of 15 conversation items
5. Generate detailed reports if vulnerabilities are found

## 🏗️ Architecture

Baby Naptime is composed of several specialized components that work together:

```
                      ┌───────────────┐
                      │  BabyNaptime  │
                      └───────┬───────┘
                              │
                              ▼
┌───────────┐           ┌───────────┐           ┌───────────┐
│    LLM    │◀─────────▶│   Agent   │─────────▶ │  Caller   │
└───────────┘           └─────┬─────┘           └───────────┘
                              │                        │
                              │                        ▼
┌───────────┐           ┌─────┴──────┐           ┌───────────┐
│  Reporter │◀──────────│ Summarizer │           │ Tool APIs │
└───────────┘           └────────────┘           └───────────┘
                                                      │
                              ┌─────────────────┬─────┴─────┬─────────────────┐
                              ▼                 ▼           ▼                 ▼
                        ┌───────────┐    ┌───────────┐┌────────────┐    ┌───────────┐
                        │CodeBrowser│    │  Debugger ││ScriptRunner│    │   Utils   │
                        └───────────┘    └───────────┘└────────────┘    └───────────┘
```

- **BabyNaptime**: Main class that initializes and coordinates all components
- **Agent**: Orchestrates the analysis workflow, maintains LLM conversation, and manages binary compilation
- **LLM**: Interface to language models (supports GPT models for now)
- **Caller**: Routes tool commands to appropriate handlers
- **Summarizer**: Condenses conversation history to maintain context within token limits
- **Reporter**: Generates comprehensive vulnerability reports with evidence
- **CodeBrowser**: Intelligently navigates code and extracts relevant segments
- **Debugger**: Provides GDB-based debugging with security analysis capabilities
- **ScriptRunner**: Executes dynamic testing scripts to validate findings
- **Utils**: Shared utility functions including token counting and formatting

## 📊 Output

The tool generates a concise, technical summary report of any discovered vulnerabilities:

```
results/
└── [filename]_summary.md
```

The summary report is a comprehensive one-page markdown document that includes:

- Executive summary of the vulnerability
- Technical analysis of the vulnerable code
- Detailed exploitation methodology
- Working payload and commands used
- Proof of successful exploitation

## 📋 TODOs

- [ ] Add support for Anthropic Claude models
- [ ] Improve code navigation for large codebases
- [ ] Enhance debugging with ASAN/Valgrind integration
- [ ] Add support for binary-only targets
- [ ] Integrate with IDA/Ghidra APIs
- [ ] Implement multi-step planning and reasoning
- [ ] Test against a large open source codebase
- [x] ~~Add basic documentation and examples~~

## 🤝 Contributing

We welcome contributions from the security community! To contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

Baby Naptime is intended for **educational and research purposes only**. Always obtain proper authorization before testing any system for vulnerabilities. The authors are not responsible for any misuse of this tool.

I am not affiliated with Google or Project Zero in any way. This is an independent project inspired by their excellent research work which I attempted to replicate as a learning exercise.

## 🙏 Acknowledgments

- Inspired by [Google's Project Naptime](https://googleprojectzero.blogspot.com/2024/06/project-naptime.html) by Project Zero researchers
- Project Naptime achieved impressive results on the [CyberSecEval2](https://github.com/meta-llama/PurpleLlama) benchmark, improving scores by up to 20x
- Thanks to the open source security community
- All the security researchers who share knowledge freely
- Claude Sonnet 3.7 which helped write a lot of the code and documentation.

---

<p align="center">Made with ❤️ by Faizan</p>