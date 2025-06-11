# 🔐 Source Data Encryption Module

## 🚀 Key Features

*   🔒 **Symmetric Text Encryption**: Encrypt and decrypt any piece of text using a password.
*   📁 **Secure File Encryption**: Encrypt and decrypt entire files (images, documents, etc.) for secure storage or transfer.
*   🔑 **Robust Key Derivation**: Uses the **SHA-256** hash of your password to generate a secure 32-byte encryption key. Your password is never used directly.
*   🛡️ **Authenticated Encryption**: Powered by `cryptography.fernet`, which ensures that encrypted data cannot be read or tampered with without the correct key.
*   🎲 **Secure Password Generator**: Instantly create strong, random passwords to use for encryption.
*   📋 **One-Click Copy**: Easily copy encrypted text to your clipboard.
*   🌙 **Modern Dark UI**: A clean, modern, and user-friendly interface with a default dark theme for a great user experience.
*   🌐 **Fully Web-Based**: No need to install any software. All cryptographic operations happen in the server's memory and are discarded after each session.

---

## 🛠️ Tech Stack

This project is built with a combination of powerful and standard Python libraries:

*   **Framework**: [Streamlit](https://streamlit.io/)
*   **Core Cryptography**: [Cryptography (Fernet)](https://cryptography.io/en/latest/fernet/)
*   **Key Derivation (Hashing)**: [hashlib (SHA-256)](https://docs.python.org/3/library/hashlib.html)
*   **Encoding**: [base64](https://docs.python.org/3/library/base64.html)
*   **UI Components**: [Streamlit-Extras](https://pypi.org/project/streamlit-extras/)
*   **Deployment**: [Streamlit Community Cloud](https://streamlit.io/cloud)

---
