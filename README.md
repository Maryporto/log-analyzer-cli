<div align="center">

# 🔍 Log Analyzer CLI

**A lightweight, zero-dependency command-line tool for web server log analysis and brute-force detection.**  
**Uma ferramenta de linha de comando leve e sem dependências externas para análise de logs web e detecção de força bruta.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)](#)

[🇺🇸 Read in English](#english) | [🇧🇷 Leia em Português](#portugues)

</div>

---
<a id="english"></a>
## 🇺🇸 English

### 📖 Overview
**Log Analyzer CLI** is a command-line interface tool built in **Python** to parse web server access logs, aggregate traffic metrics, and automatically flag suspicious security patterns such as brute-force login attempts.

Developed using **only the Python Standard Library (Zero Dependencies)**, it ensures high portability, low memory footprint, and seamless execution across Linux, macOS, and Windows environments.

### ✨ Features
* **Structured Regex Parsing:** Extracts IP address, timestamp, HTTP method, requested endpoint, status code, and response size.
* **Brute-Force Detection:** Identifies and alerts on IP addresses exceeding a configurable threshold of authentication failures (`HTTP 401` and `HTTP 403`).
* **Traffic Metrics:** Ranks the most active IPs, most accessed endpoints, and HTTP status code distribution.
* **JSON Export:** Exports consolidated reports in `.json` format for easy integration with SIEM tools, scripts, or dashboards.
* **Memory-Efficient Streaming:** Reads files line by line, capable of processing gigabyte-sized logs with constant $O(1)$ memory usage.

### 🛠️ Tech Stack
* **Python 3.10+**
* **`argparse`:** CLI flags, argument validation, and automated `--help` menu generation.
* **`re`:** Pre-compiled regular expressions with named capture groups for clean data extraction.
* **`collections.Counter`:** High-performance frequency counting and ranking.
* **`pathlib` & `json`:** Cross-platform file path handling and report serialization.

### 🚀 Getting Started

#### Prerequisites
Make sure **Python 3.10 or higher** is installed:
```bash```

---

<a id="portugues"></a>
## 🇧🇷 Português

### 📖 Visão Geral
O **Log Analyzer CLI** é uma ferramenta de linha de comando desenvolvida em **Python** para analisar logs de acesso de servidores web, contabilizar métricas de tráfego e detectar automaticamente padrões suspeitos de segurança, como tentativas de ataque de força bruta.

Construído inteiramente com a **biblioteca padrão do Python (Zero Dependencies)**, garante alta portabilidade, baixo consumo de memória e execução imediata em ambientes Linux, macOS e Windows.

### ✨ Funcionalidades
* **Parsing Estruturado via Regex:** Extração de endereço IP, timestamp, método HTTP, endpoint acessado, código de status e tamanho da resposta.
* **Detecção de Força Bruta:** Identifica e alerta sobre IPs que ultrapassam um limite configurável de falhas de autenticação (`HTTP 401` e `HTTP 403`).
* **Métricas de Tráfego:** Ranqueia os IPs mais ativos, os endpoints mais requisitados e a distribuição de códigos de status HTTP.
* **Exportação em JSON:** Permite salvar os resultados consolidados em formato `.json` para integração com ferramentas SIEM, scripts ou dashboards.
* **Processamento em Streaming:** Lê arquivos linha por linha, permitindo processar logs de gigabytes mantendo o consumo de memória RAM constante ($O(1)$).

### 🛠️ Tecnologias Utilizadas
* **Python 3.10+**
* **`argparse`:** Flags de linha de comando, validação de argumentos e geração automática do menu `--help`.
* **`re`:** Expressões regulares pré-compiladas com grupos nomeados para extração limpa de dados.
* **`collections.Counter`:** Contagem otimizada de frequências e rankings.
* **`pathlib` & `json`:** Manipulação multiplataforma de caminhos de arquivos e serialização de relatórios.

### 🚀 Como Começar

#### Pré-requisitos
Certifique-se de ter o **Python 3.10 ou superior** instalado:
```bash
python --version
