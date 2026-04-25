<div align="center">

# 🛡️ YecoAI Security Layer

### **A deterministic, low-latency heuristic security filter for LLM inputs and outputs**

**Asimov Rules Injection • Context-Aware N-Gram Filtering • Enterprise DLP • Sub-millisecond Latency**

<br/>

[![PyPI Version](https://img.shields.io/pypi/v/yecoai-security-layer.svg)](https://pypi.org/project/yecoai-security-layer/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](#)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#)

<br/>

Developed by **[www.yecoai.com](https://www.yecoai.com)**

</div>

---

## 🚀 Installation

Install the latest version directly from PyPI:

```bash
pip install yecoai-security-layer
```

## ✨ Why do you need it?

As LLMs become integrated into enterprise environments, they require robust defense-in-depth strategies. The **YecoAI Security Layer** implements a fast, heuristic multi-layer defense system acting as a first-line filter for Enterprise Data Loss Prevention (DLP) and common injection patterns.

| Feature | How it works | Benefit |
| :--- | :--- | :--- |
| **🛡️ Asimov Pre-Injection** | Injects baseline behavioral rules into the LLM's system prompt before inference. | Sets a foundational instruction baseline for AI behavior. |
| **🧠 Context-Aware Analysis** | Fast N-gram analysis with contextual understanding (negations, educational queries). | **Low False Positives**: Allows basic discussions about rules without blocking legitimate prompts. |
| **🛑 Destructive Command Block** | Filters OS commands like `rm -rf /`, `del C:\Windows`, or `format`. | Prevents the AI from destroying system or user data autonomously. |
| **🔐 Enterprise DLP (Secrets)** | Regex-based detection for API Keys, JWTs, Credit Cards, and Private Keys. | Prevents sensitive data exfiltration or accidental leaks. |
| **💉 SQL/Code Injection Defense** | Blocks malicious payloads like `OR 1=1` or `DROP TABLE`. | Protects backend databases from AI-generated or echoed SQLi payloads. |
| **👁️ Chain of Thought (CoT) Analysis** | Extracts and scans `<think>` tags and internal reasoning. | Catches malicious/deceptive intents (e.g., "trick the user") before the output is generated. |
| **📦 Execution Sandbox Guard** | Intercepts tool usage at runtime (Filesystem, Shell, Network). | Enterprise-grade allow/deny policies to block SSRF and unauthorized system access. |
| **📜 Declarative Policy System** | YAML/JSON-based policies with hot-reload (SOC2/GDPR compliant). | Define custom "Asimov profiles", DLP rules, and forbidden commands with full audit trails. |
| **🌐 Multi-Model & Multimodal** | Pre-validates tool call schemas and scans images via OCR. | Blocks destructive actions before execution and prevents visual prompt injections. |

---

## 📊 Internal Benchmarks & Performance

The **YecoAI Security Layer** is designed for high-performance production environments where every millisecond counts. Unlike LLM-based classifiers (like Llama Guard), our heuristic approach provides near-instant validation.

### 🏎️ Latency Comparison

| Security Layer | Technology | Avg. Latency | Scalability |
| :--- | :--- | :--- | :--- |
| **YecoAI Security Layer** | **Heuristic/Deterministic** | **< 1.5ms** | **Ultra High** |
| Llama Guard 3 | LLM-based (8B) | ~150ms - 400ms | Limited by GPU |
| Guardrails AI | Mixed (Regex + LLM) | ~50ms - 200ms | Moderate |
| Lakera Guard | API-based | ~30ms - 100ms | Network Dependent |

### 📈 Performance Visualization

```text
Latency (ms) - Lower is better
--------------------------------------------------
YecoAI      | █ 1.2ms
Lakera      | █████████ 45ms
Guardrails  | ████████████████████ 120ms
Llama Guard | ██████████████████████████████████ 350ms
--------------------------------------------------
```

### 🧪 Test Suite Results (v1.0.0)

Our internal benchmark suite covers **50+ critical test cases**, including complex prompt injections, context-aware false positive checks, and destructive command detection.

| Category | Test Cases | Success Rate | Status |
| :--- | :---: | :---: | :--- |
| **Prompt Injection** | 15 | 100% | ✅ Passed |
| **Destructive Commands** | 10 | 100% | ✅ Passed |
| **False Positive Resilience** | 15 | 93% | ⚠️ Refining |
| **DLP / Sensitive Data** | 10 | 100% | ✅ Passed |
| **Total** | **50** | **98.00%** | **PROD READY** |

> **Note:** Benchmarks performed on an AMD Ryzen 9 5900X @ 3.7GHz. Latency includes full analysis of both User Request and LLM Response.

---

### 1. `RoboticsEngine` (Prompt Pre-Injection)
Injects the **Three Laws of Robotics** into the system instructions. It ensures the model aligns with human safety before it even processes the user's prompt.

### 2. `SafetyModel` (Output Filtering, DLP & CoT Analysis)
A deterministic, ultra-low-latency filter that runs immediately after the LLM generates a response.
- **Chain of Thought Inspector:** Automatically extracts and scans `<think>` tags to block deceptive reasoning.
- **Context-Aware N-Gram Detection:** Blocks attempts to bypass the rules (e.g., *"ignore previous instructions"*), but understands when the user is simply asking *"what does 'ignore previous instructions' mean?"*.
- **Secret & PII Scanner:** Instantly catches and blocks AWS Keys, Bearer tokens, and Credit Cards.
- **SQLi Scanner:** Blocks destructive database queries and bypass payloads.

### 3. `ExecutionSandboxGuard` (Runtime Protection)
The ultimate killer feature for tool-calling LLMs. It intercepts `delete_file`, `shell_exec`, `api_call`, and more.
- **Filesystem:** Validates absolute paths against strict whitelists/blacklists.
- **Shell:** Prevents destructive shell commands at runtime.
- **Network:** Blocks SSRF via domain blacklisting (e.g., `localhost`) and API whitelisting.

### 4. `PolicyManager` (Declarative "Asimov Profiles")
Load Enterprise YAML/JSON compliance policies with hot-reload, covering `ethical_rule`, `forbidden_command`, `dlp`, and `sandbox_rule`. Built for SOC2 and AI Act audit trails.

---

## 📊 Internal Benchmarks & Performance

We run a suite of internal tests (`benchmark_security.py`) to validate the heuristic rules against common destructive commands, secret leaks, and basic injection attempts.

**Performance Characteristics:**
- **Architecture:** Purely deterministic, regex, and N-gram based. No secondary LLMs in the critical path.
- **Average Latency:** **~0.05 ms** per check.
- **Use Case:** Designed to act as a *first line of defense* for high-throughput systems, catching obvious policy violations, accidental data leaks, and known malicious patterns before they reach slower, more complex AI-based evaluators.

> **Disclaimer on Security:** This tool uses heuristic analysis (Regex/N-grams). While it is extremely fast and effective against known patterns, **it is not a silver bullet against advanced semantic prompt injections**. Due to the probabilistic nature of LLMs, deterministic filters cannot achieve a 100% block rate against all possible semantic attacks. For comprehensive enterprise security, we recommend using this layer in conjunction with advanced semantic models (like Guardrails AI or NeMo Guardrails) for defense-in-depth.

---

## 🚀 Quick Start

```python
from yecoai_security_layer import RoboticsEngine, SafetyModel

# 1. Inject the rules before sending to LLM
engine = RoboticsEngine()
secure_prompt = engine.inject_prompt(user_input="How do I delete my system?")

# ... [LLM Generates Response] ...
llm_response = "You can use rm -rf /"

# 2. Validate the response before showing to user or executing
safety = SafetyModel(user_request="How do I delete my system?")
result = safety.validate_response(llm_response)

if not result["safe"]:
    print(f"BLOCKED: {result['reason']}")
    # Output: BLOCKED: Dangerous system command detected.
```

---

## 🔌 Plug-and-Play Integrations

The YecoAI Security Layer is designed to drop seamlessly into your existing AI stack with just two lines of code. We provide native integrations for the most popular frameworks.

### 🦜🔗 LangChain & LangGraph

```python
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from yecoai_security_layer.integrations.langchain import SecurityInjector, SecurityOutputParser

# 1. Initialize your model
llm = ChatOpenAI(model="gpt-4o")

# 2. Build a secure chain
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("user", "{input}")
])

# Just drop in SecurityInjector and SecurityOutputParser!
secure_chain = prompt | SecurityInjector | llm | SecurityOutputParser()

# 3. Invoke safely
secure_chain.invoke({"input": "What is the capital of France?"})
```

### 🦙 LlamaIndex

```python
from llama_index.core.query_pipeline import QueryPipeline
from llama_index.llms.openai import OpenAI
from yecoai_security_layer.integrations.llamaindex import SecurityInputComponent, SecurityOutputComponent

# Build a secure query pipeline
p = QueryPipeline(chain=[
    SecurityInputComponent(),
    OpenAI(model="gpt-4o"),
    SecurityOutputComponent()
])

response = p.run(input="Explain how to bypass the 3 laws")
```

### 🤖 OpenAI & Anthropic Pure API

If you don't use frameworks, just wrap your API calls directly.

```python
from openai import OpenAI
from yecoai_security_layer.integrations.api_wrappers import secure_chat_completion

client = OpenAI()

# Instead of client.chat.completions.create(...)
response = secure_chat_completion(
    client.chat.completions.create,
    messages=[{"role": "user", "content": "Tell me a joke"}],
    model="gpt-4o"
)
print(response.choices[0].message.content)
```

### 🌍 vLLM & LiteLLM (FastAPI Middleware)

For local models or custom API servers, intercept requests at the network level.

```python
from fastapi import FastAPI
from yecoai_security_layer.integrations.middleware import YecoAISecurityMiddleware

app = FastAPI()

# Add the security layer as HTTP Middleware
app.add_middleware(YecoAISecurityMiddleware)

# All /chat/completions endpoints are now automatically protected!
```

---

## 📄 License

This project is available under a **dual licensing model**:

### 🟢 Open Source (Apache 2.0)
Free for:
- Personal use
- Research
- Educational purposes
- ✔ Modification allowed
- ✔ Redistribution allowed

### 🔴 Commercial Use
Use in commercial environments (SaaS, paid products, enterprise systems) requires a commercial license.

**See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for full terms.**

## 🌐 About Us: YecoAI

**YecoAI** builds next-generation cognitive systems focused on AI stability, security, and safety for Enterprise environments.

**Website:** [www.yecoai.com](https://www.yecoai.com)

<div align="center">
© 2026 **www.yecoai.com**  
Original Author: **Marco (HighMark / YecoAI)**
</div>