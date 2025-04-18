# CryptoUtils 加密工具库

一个用 Java 编写的加密工具库，展示了多种常见的加密算法与技术实现方式

# 使用 maven/gradle 导入
https://jitpack.io/#LangYa466/CryptoUtils/-SNAPSHOT
---

## 功能简介

本工具库提供以下加密功能：

### 🔐 对称加密/解密（共享密钥加密）

- **AES-GCM**（具备认证的加密，推荐使用）
- **AES-CBC**（需要额外的完整性校验）
- **ChaCha20-Poly1305**（具备认证的加密，推荐使用，需 Java 11 及以上）
- **DES-CBC**（已不安全，仅供学习参考）

### 🔑 非对称加密/解密（公钥/私钥）

- **RSA**（适合用于密钥交换或加密少量数据）

### 🔏 基于密码的密钥派生

- **PBKDF2WithHmacSHA256**（可根据用户密码生成加密密钥）

### 🛡️ 消息完整性与身份认证

- **HMAC-SHA256**（基于哈希的消息认证码）

### 📜 经典加密算法（已不安全，仅作教学用途）

- **凯撒加密（Caesar Cipher）**

### 🧰 密钥生成工具

- 支持生成 AES、DES、ChaCha20 和 RSA 所需密钥

### ⚙️ 辅助工具类

- 安全随机的 IV（初始化向量）/Nonce 生成
- Base64 编码与解码

## 💡 使用示例

如需查看所有加密算法的详细使用方式，请参考文件(src/test/java/cn/langya/Main)中的 `main` 方法：
