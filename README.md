<!-- <p align="center">
  <img src="https://raw.githubusercontent.com/PKief/vscode-material-icon-theme/ec559a9f6bfd399b82bb44393651661b08aaf7ba/icons/folder-markdown-open.svg" width="20%" alt="TESSERA-logo">
</p> -->
<p align="center">
    <h1 align="center">🔐 Tessera</h1>
</p>
<p align="center">
    <em>Scalable, Secure, and Decentralized Secret Management</em>
</p>
<p align="center">
	<img src="https://img.shields.io/github/license/CremitHQ/tessera?style=default&logo=opensourceinitiative&logoColor=white&color=0080ff" alt="license">
	<img src="https://img.shields.io/github/last-commit/CremitHQ/tessera?style=default&logo=git&logoColor=white&color=0080ff" alt="last-commit">
	<img src="https://img.shields.io/github/languages/top/CremitHQ/tessera?style=default&color=0080ff" alt="repo-top-language">
	<img src="https://img.shields.io/github/languages/count/CremitHQ/tessera?style=default&color=0080ff" alt="repo-language-count">
</p>
<p align="center">
	<!-- default option, no dependency badges. -->
</p>
<br>

## 🔗 Table of Contents

- [🔗 Table of Contents](#-table-of-contents)
- [📍 Overview](#-overview)
- [👾 Features](#-features)
- [🚀 Getting Started](#-getting-started)
  - [☑️ Prerequisites](#️-prerequisites)
  - [⚙️ Installation](#️-installation)
  - [🤖 Usage](#-usage)
  - [🧪 Testing](#-testing)
- [🔰 Contributing](#-contributing)
- [🎗 License](#-license)

---

## 📍 Overview

Tessera is an open-source secret management platform engineered to revolutionize how organizations protect and manage sensitive information. By leveraging advanced cryptographic protocols—specifically Multi-Authority Attribute-Based Encryption (MA-ABE)—Tessera provides a decentralized, flexible, and highly scalable solution for secure secret storage and granular access control.

Designed to meet the rigorous security demands of modern enterprises, Tessera addresses the complex challenges of secret management across multiple domains and organizations. It offers a robust framework that not only enhances security but also adapts to the evolving needs of diverse systems.

---

## 👾 Features

|      | Feature         | Summary       |
| :--- | :---:           | :---          |
| ⚙️ | **Decentralized Architecture**  | <ul><li>Eliminates single points of failure by distributing authority across multiple trusted entities.</li><li>Enhances overall system security and resilience against targeted attacks.</li></ul> |
| 🔐 | **End-to-End Encryption**  | <ul><li>Ensures all encryption and decryption processes occur on the client side.</li><li>Guarantees that unencrypted secrets never leave the user’s device.</li></ul> |
| 📝 | **Audit** | <ul><li>Provides detailed logs of access events, changes, and system activities.</li><li>Supports compliance requirements by enabling thorough security audits.</li><li>Enhances transparency and accountability within the organization.</li></ul> |
| 🔌 | **Integrations**  | <ul><li>Offers intuitive APIs and SDKs for seamless integration into applications and workflows.</li><li>Supports WebAssembly (`tessera-abe-wasm`) for cross-platform compatibility and performance-critical tasks.</li><li>Minimizes the learning curve and accelerates deployment times.</li></ul> |
| 🎛️ | **Advanced Access Control**       | <ul><li>Enables fine-grained access control based on user attributes and roles.</li><li>Allows for the definition and enforcement of complex access policies across multiple authorities.</li><li>Supports secure collaboration and secret sharing in multi-organizational environments.</li></ul> |
| ⚡️  | **Performance**   | <ul><li>Designed to scale effortlessly from startups to large enterprises.</li><li>Utilizes efficient cryptographic operations optimized for speed and security.</li></ul> |
| 🛡️ | **Security**      | <ul><li>Supports various authentication methods.</li><li>Secure data handling with AES-GCM encryption for storage operations.</li><li>Facilitates multi-factor and federated authentication setups.</li></ul> |

---

## 🚀 Getting Started

### ☑️ Prerequisites

Before getting started with tessera, ensure your runtime environment meets the following requirements:

- **Programming Language:** Rust
- **Package Manager:** Cargo


### ⚙️ Installation

Install tessera using one of the following methods:

**Build from source:**

1. Clone the tessera repository:
```sh
❯ git clone https://github.com/CremitHQ/tessera
```

2. Navigate to the project directory:
```sh
❯ cd tessera
```

3. Build the project:


**Using `cargo`** &nbsp; [<img align="center" src="https://img.shields.io/badge/Rust-000000.svg?style={badge_style}&logo=rust&logoColor=white" />](https://www.rust-lang.org/)

```sh
❯ cargo build -p $PACKAGE_NAME
```




### 🤖 Usage
Run tessera using the following command:
**Using `cargo`** &nbsp; [<img align="center" src="https://img.shields.io/badge/Rust-000000.svg?style={badge_style}&logo=rust&logoColor=white" />](https://www.rust-lang.org/)

```sh
❯ cargo run -p $PACKAGE_NAME
```


### 🧪 Testing
Run the test suite using the following command:
**Using `cargo`** &nbsp; [<img align="center" src="https://img.shields.io/badge/Rust-000000.svg?style={badge_style}&logo=rust&logoColor=white" />](https://www.rust-lang.org/)

```sh
❯ cargo test
```




---

## 🔰 Contributing

- **💬 [Join the Discussions](https://github.com/CremitHQ/tessera/discussions)**: Share your insights, provide feedback, or ask questions.
- **🐛 [Report Issues](https://github.com/CremitHQ/tessera/issues)**: Submit bugs found or log feature requests for the Tessera project.
- **💡 [Contributing Guidelines](./CONTRIBUTING.md)**: Contributing to the Tessera project.


<details open>
<summary>Contributor Graph</summary>
<br>
<p align="left">
   <a href="https://github.com{/CremitHQ/tessera/}graphs/contributors">
      <img src="https://contrib.rocks/image?repo=CremitHQ/tessera">
   </a>
</p>
</details>

---

## 🎗 License

This project is licensed under the [Apache License 2.0](./LICENSE). You are free to use, modify, and distribute this software under the terms of this license.
