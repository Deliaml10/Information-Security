#include <stdio.h>
#include <stdlib.h>
#include <string.h> 

const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/";

void encryptionARRAY(char *input, char *key){
    int inputlen = strlen(input);
    int keylen = strlen(key);
    int alphabetlen = strlen(alphabet);

    char *encrypted = malloc((inputlen + 1) * sizeof(char));
    if (encrypted == NULL) {
        printf("Error.\n");
        return;
    }

    
    for (int i = 0, j = 0; i < inputlen; i++) {
        char c = input[i];
        char *pos = strchr(alphabet, c);
        if (pos) {
            int index = pos - alphabet;
            int key_index = strchr(alphabet, key[j % keylen]) - alphabet;
            c = alphabet[(index + key_index) % alphabetlen];
            j++;
        }
        encrypted[i] = c;
    }

    encrypted[inputlen] = '\0';
    printf("Encrypted text: %s\n", encrypted);

    free(encrypted);
}

//Funtion for ARRAY decription
void decryptionARRAY(char *encrypted, char *key){
    int inputlen = strlen(encrypted);
    int keylen = strlen(key);
    int alphabetlen = strlen(alphabet);

    char *decrypted = malloc((inputlen + 1) * sizeof(char));
    if (decrypted == NULL) {
        printf("Error.\n");
        return;
    }
    
    for (int i = 0, j = 0; i < inputlen; i++) {
        char c = encrypted[i];
        char *pos = strchr(alphabet, c);
        if (pos) {
            int index = pos - alphabet;
            int key_index = strchr(alphabet, key[j % keylen]) - alphabet;
            c = alphabet[(index - key_index + alphabetlen) % alphabetlen];
            j++;
        }
        decrypted[i] = c;
    }
    decrypted[inputlen] = '\0';
    printf("Decrypted text: %s\n", decrypted);

    free(decrypted);
}

//Function for ASCII encryption
void encryptionASCII(char *input, char *key){
    int inputlen = strlen(input);
    int keylen = strlen(key);

    char *encrypted = malloc((inputlen + 1) * sizeof(char));
    if (encrypted == NULL) {
        printf("Error.\n");
        exit(-1);
    }

//Algorithm for ASCII encryption using Veginere cipher    
for (int i = 0; i < inputlen; i++) {
    if (input[i] >= 32 && input[i] <= 126) {
        int key_index = (key[i % keylen] - 32);
        encrypted[i] = 32 + ((input[i] - 32 + key_index) % 95);
    } else {
        encrypted[i] = input[i]; 
    }
}

    encrypted[inputlen] = '\0';
    printf("Encrypted text: %s\n", encrypted);

    free(encrypted);
}


//Function for ASCII decryption
void decryptionASCII(char *encrypted, char *key){
    int inputlen = strlen(encrypted);
    int keylen = strlen(key);

    char *decrypted = malloc((inputlen + 1) * sizeof(char));
    if (decrypted == NULL) {
        printf("Error.\n");
        exit(-1);
    }

// Algorithm for decryption using the opposite Veginere cipher
for (int i = 0; i < inputlen; i++) {
    if (encrypted[i] >= 32 && encrypted[i] <= 126) { 
        int key_index = (key[i % keylen] - 32);
        decrypted[i] = 32 + ((encrypted[i] - 32 - key_index + 95) % 95);
    } else {
        decrypted[i] = encrypted[i]; 
    }
}
 
    decrypted[inputlen] = '\0';
    printf("Decrypted text: %s\n", decrypted);

    free(decrypted);
}

int main(){
    char option;
    char option2;
    char input[256];
    char key[256];
    char encrypt[256];
    char key2[256];

    printf("1. ASCII\n");
    printf("2. ARRAY\n");
    printf("Choose the type of encryption: ");
    scanf(" %c", &option);
    getchar();

    printf("Enter the input string: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';

    printf("Enter the key for encryption: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';

    if(option == '1'){
        encryptionASCII(input, key);
    } else if(option == '2'){
        encryptionARRAY(input, key);
    } else {
        printf("Invalid option.\n");
        return -1;
    }

    printf("1. ASCII\n");
    printf("2. ARRAY\n");
    printf("Choose the type of decryption: ");
    scanf(" %c", &option2);
    getchar();

    printf("Enter the encrypted text to decrypt: ");
    fgets(encrypt, sizeof(encrypt), stdin);
    encrypt[strcspn(encrypt, "\n")] = '\0';

    printf("Enter the key for decryption: ");
    fgets(key2, sizeof(key2), stdin);
    key2[strcspn(key2, "\n")] = '\0';

    if(option2 == '1'){
        decryptionASCII(encrypt, key2);
    } else if(option2 == '2'){
        decryptionARRAY(encrypt, key2);
    } else {
        printf("Invalid option.\n");
        return -1;
    }

    return 0;
}
