# 🔐 Secure Communication Project

This project demonstrates a secure communication system between client and server using **hybrid encryption (RSA + AES)** over a raw TCP socket.

---

## 🔧 Objective

Enable encrypted command execution over TCP using:

- Symmetric encryption (**AES-256-CBC**)  
- Asymmetric encryption (**RSA 2048**)  
- Socket communication  
- JSON messaging  
- OpenSSL + C

---

## 📦 Requirements

**Install dependencies:**

```bash
sudo apt install libssl-dev libcjson-dev netcat
```

---

## 🔑 Generate RSA Keys

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

---

## 🛠️ Compilation

```bash
gcc client.c -o client -lcrypto
gcc server.c -o server -lcrypto -lcjson
```

---

## 🚀 Usage

### On the server:

```bash
./server
```

### On the client:

```bash
./client
```

Example input:

```bash
ls -la
```

---

## 🧱 File Structure

- `client.c` — Secure client using hybrid encryption  
- `server.c` — Secure server that decrypts and executes commands  
- `public.pem` — Public RSA key used by the client  
- `private.pem` — Private RSA key used by the server  

---

## ⚠️ Legal Disclaimer

> This project is intended **for educational and research purposes only**.  
> Do not use this code for unauthorized access, attack automation, or production systems.  
> You are solely responsible for how you use it.

---

## 👨‍💻 Author

**Rafael Medeiros**  
Maintained by [alby.technology](https://alby.technology)

---

# 🇧🇷 Projeto de Comunicação Segura

Este projeto demonstra uma comunicação segura entre cliente e servidor usando **criptografia híbrida (RSA + AES)** via socket TCP puro.

---

## 🔧 Objetivo

Executar comandos criptografados com:

- Criptografia simétrica (**AES-256-CBC**)  
- Criptografia assimétrica (**RSA 2048**)  
- Comunicação via sockets  
- Troca de dados em JSON  
- Uso da OpenSSL em C  

---

## 📦 Requisitos

**Instale as dependências:**

```bash
sudo apt install libssl-dev libcjson-dev netcat
```

---

## 🔑 Gerar as Chaves RSA

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

---

## 🛠️ Compilar

```bash
gcc client.c -o client -lcrypto
gcc server.c -o server -lcrypto -lcjson
```

---

## 🚀 Execução

### Servidor:

```bash
./server
```

### Cliente:

```bash
./client
```

Exemplo de comando:

```bash
ls -la
```

---

## 📁 Estrutura dos Arquivos

- `client.c` — Cliente com criptografia híbrida  
- `server.c` — Servidor que decifra e executa os comandos  
- `public.pem` — Chave pública RSA usada pelo cliente  
- `private.pem` — Chave privada RSA usada pelo servidor  

---

## ⚠️ Aviso Legal

> Este projeto é **exclusivamente para fins educacionais e de pesquisa**.  
> Não utilize este código para acessos não autorizados ou em ambientes de produção.  
> O uso indevido é de responsabilidade exclusiva do usuário.

---

## 👨‍💻 Autor

**Rafael Medeiros**  
Mantido por [alby.technology](https://alby.technology)

---

# 🇸🇦 ملف README - مشروع الاتصال الآمن

يعرض هذا المشروع نظام اتصال آمن بين العميل والخادم باستخدام **تشفير هجين (RSA + AES)** عبر بروتوكول TCP.

---

## 🎯 الهدف

تنفيذ أوامر آمنة باستخدام:

- تشفير متماثل (**AES-256-CBC**)  
- تشفير غير متماثل (**RSA 2048**)  
- الاتصال عبر TCP sockets  
- تبادل بيانات بتنسيق JSON  
- استخدام مكتبة OpenSSL بلغة C  

---

## 🧰 المتطلبات

**لتثبيت الحزم المطلوبة:**

```bash
sudo apt install libssl-dev libcjson-dev netcat
```

---

## 🔐 توليد المفاتيح RSA

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

---

## ⚙️ الترجمة

```bash
gcc client.c -o client -lcrypto
gcc server.c -o server -lcrypto -lcjson
```

---

## 🚀 الاستخدام

### على الخادم:

```bash
./server
```

### على العميل:

```bash
./client
```

مثال على الأمر:

```bash
ls -la
```

---

## 🗂️ هيكل الملفات

- `client.c` — عميل يستخدم تشفيرًا هجينًا  
- `server.c` — خادم يفك التشفير وينفذ الأوامر  
- `public.pem` — المفتاح العام المستخدم من قبل العميل  
- `private.pem` — المفتاح الخاص المستخدم من قبل الخادم  

---

## ⚠️ تنبيه قانوني

> هذا المشروع مخصص **لأغراض تعليمية وبحثية فقط**.  
> لا تستخدم هذا الكود في بيئات الإنتاج أو للوصول غير المصرح به.  
> أي استخدام خاطئ هو على مسؤوليتك الخاصة.

---

## 👨‍💻 المؤلف

**رافاييل ميديروس**  
تم تطوير المشروع بواسطة [alby.technology](https://alby.technology)
