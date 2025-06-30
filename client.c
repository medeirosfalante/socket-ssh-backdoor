#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char *base64_encode(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);
    return buff;
}

int main()
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    char message[1024];

    // Criar socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Erro na criação do socket\n");
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        printf("Endereço inválido\n");
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("Erro na conexão\n");
        return -1;
    }

    while (1)
    {
        printf("Escreva a mensagem: ");
        fgets(message, sizeof(message), stdin);
        if (strcmp(message, "exit\n") == 0)
            break;

        // Gera chave AES e IV
        unsigned char aes_key[32], aes_iv[16];
        RAND_bytes(aes_key, sizeof(aes_key));
        RAND_bytes(aes_iv, sizeof(aes_iv));

        // Criptografa comando
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char ciphertext[1024];
        int len, ciphertext_len;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)message, strlen(message));
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        // Codifica payload
        char *payload_b64 = base64_encode(ciphertext, ciphertext_len);

        // Lê chave pública RSA
        FILE *pubkey_file = fopen("public.pem", "r");
        if (!pubkey_file)
        {
            perror("Erro ao abrir public.pem");
            return -1;
        }
        RSA *rsa_pub = PEM_read_RSA_PUBKEY(pubkey_file, NULL, NULL, NULL);
        fclose(pubkey_file);
        if (!rsa_pub)
        {
            perror("Erro ao carregar chave pública");
            return -1;
        }

        // Junta chave+IV
        unsigned char key_iv[48];
        memcpy(key_iv, aes_key, 32);
        memcpy(key_iv + 32, aes_iv, 16);

        unsigned char encrypted_key_iv[256];
        int encrypted_len = RSA_public_encrypt(sizeof(key_iv), key_iv, encrypted_key_iv, rsa_pub, RSA_PKCS1_OAEP_PADDING);
        RSA_free(rsa_pub);

        // Codifica chave
        char *keyblob_b64 = base64_encode(encrypted_key_iv, encrypted_len);

        // Monta JSON
        char json[4096];
        snprintf(json, sizeof(json),
                 "{\n  \"keyblob\": \"%s\",\n  \"payload\": \"%s\"\n}\n",
                 keyblob_b64, payload_b64);

        send(sock, json, strlen(json), 0);

        free(payload_b64);
        free(keyblob_b64);

        // Recebe resposta
        char response[2048] = {0};
        read(sock, response, sizeof(response));
        printf("Servidor respondeu:\n%s\n", response);
    }

    close(sock);
    return 0;
}
