#include <stdio.h>
#include <sodium.h>
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#define MESSAGE_LEN 10240 // 1024 bytes
#define CIPHERTEXT_LEN_MESSAGE (MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES) // 10240 + 16 bytes
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define BASE64_LEN 44

using namespace std;

unsigned char publicKey25519[crypto_scalarmult_curve25519_BYTES];  // use 32 bytes
unsigned char secretKey25519[crypto_scalarmult_curve25519_BYTES];  // use 32 bytes
unsigned char sharesKey25519[crypto_scalarmult_curve25519_BYTES]; // user 32 bytes

unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char MESSAGES[MESSAGE_LEN];
unsigned char CIPHERTEXT[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];


void createPublicKeyAndSecretKey(char secretKey[],char publicKey[]);
void encrypto_messages(char file_message[],char file_ciphertext[]);
void decrypto_messages(char file_ciphertext[],char file_message[]);
string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
string base64_decode(std::string const& encoded_string);
inline bool is_base64(unsigned char c);

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

void createPublicKeyAndSecretKey(char secretKey[],char publicKey[]) {

    unsigned char publicKeyEd25519[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char secretKeyEd25519[crypto_sign_ed25519_SECRETKEYBYTES];
    /*
    * convert ed25519 to curver295519
    */
    crypto_sign_ed25519_keypair(publicKeyEd25519,secretKeyEd25519);
    if(crypto_sign_ed25519_pk_to_curve25519(publicKey25519, publicKeyEd25519) == 0
                    && crypto_sign_ed25519_sk_to_curve25519(secretKey25519,secretKeyEd25519) == 0){
        printf("\nCreate Key Successfully!!!\n");
    }
    /*
    * write public key and secret key
    */

    FILE *out = fopen(secretKey,"w");
    if(out == NULL) {
        printf("\nWrite secretKey Fail");
        exit(EXIT_FAILURE);
    }else {
        string secret = base64_encode(secretKey25519,crypto_scalarmult_curve25519_BYTES);
        int len = secret.length();
        fprintf(out,"---------------- SECERT KEY ----------------\n");
        fwrite(secret.c_str(),1,len,out);
        fprintf(out,"\n--------------------------------------------");
    }
    fclose(out);
    FILE *inp = fopen(publicKey,"w");
    if(inp == NULL) {
        printf("\nWrite publicKey Fail");
        exit(EXIT_FAILURE);
    }else {
        string pub = base64_encode(publicKey25519,crypto_scalarmult_curve25519_BYTES);
        int len = pub.length();
        fprintf(inp,"---------------- PUBLIC KEY ----------------\n");
        fwrite(pub.c_str(),1,len,inp);
        fprintf(inp,"\n--------------------------------------------");

        /*
        *  printf public key
        */
        printf("\n---------------- PUBLIC KEY ----------------\n");
        printf("%s",pub.c_str());
        printf("\n--------------------------------------------\n");
    }
    fclose(inp);

}

void copyKey(unsigned char *a,const char* b,int len) {
    for(int i =0 ;i < len;i++) {
        a[i] = b[i];
    }
}

void loadPublicKeyOfPartnerAndMySecretKey(char publickey[],char secretkey[]) {
    /*
    * read publicKeyOfPartner
    */
    FILE *inp = fopen(publickey,"r");
    if(inp == NULL) {
        printf("\nCan't read publicKey");
        exit(EXIT_FAILURE);
    }else {
        unsigned char pub[BASE64_LEN];
        fread(pub,1,BASE64_LEN,inp);
        fscanf(inp,"%c",&pub[BASE64_LEN - 1]);
        fread(pub,1,BASE64_LEN,inp);
        pub[BASE64_LEN] = '\0';
        string s((char*)pub);
        copyKey(publicKey25519,base64_decode(s).c_str(),crypto_scalarmult_curve25519_BYTES);
    }
    publicKey25519[crypto_scalarmult_curve25519_BYTES] = '\0';
    fclose(inp);
    /*
    * write MysecretKey
    */
    FILE *out = fopen(secretkey,"r");
    if(out == NULL) {
        printf("\nCan't read secretKey");
        exit(EXIT_FAILURE);
    }else {
        unsigned char secret[BASE64_LEN];
        fread(secret,1,BASE64_LEN,out);
        fscanf(out,"%c",&secret[BASE64_LEN - 1]);
        fread(secret,1,BASE64_LEN,out);
        secret[BASE64_LEN] = '\0';
        string s((char*)secret);
        copyKey(secretKey25519,base64_decode(s).c_str(),crypto_scalarmult_curve25519_BYTES);
    }
    secretKey25519[crypto_scalarmult_curve25519_BYTES] = '\0';
    fclose(out);
    // read successfully
}

inline bool is_base64(unsigned char c) {

  return (isalnum(c) || (c == '+') || (c == '/'));

}

string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {

  string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {

      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }
  return ret;

}


string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}
/*
void loadAndWriteNonce(char non[],char checked) {
    if(checked == 'r') {
        FILE *inp = fopen(non,"r");
        if(inp == NULL) {
            printf("\nCan't read Nonce");
            exit(EXIT_FAILURE);
        }else {
            for(int i = 0;i < crypto_secretbox_NONCEBYTES;i++) {
                fscanf(inp,"%c",&nonce[i]);
            }
        }
    }else {
        randombytes_buf(nonce, sizeof nonce);
        FILE *inp = fopen(non,"w");
        if(inp == NULL) {
            printf("\nCan't write Nonce");
            exit(EXIT_FAILURE);
        }else {
             for(int i = 0;i < crypto_secretbox_NONCEBYTES;i++) {
                fprintf(inp,"%c",nonce[i]);
            }
        }
    }
}
*/

void WriteFile(char non[],unsigned char key[],int len) {
        FILE *inp = fopen(non,"wb");
        if(inp == NULL) {
            printf("\nCan't write Nonce");
            exit(EXIT_FAILURE);
        }else {
            fwrite(CIPHERTEXT,1,len,inp);
        }
}

void clearMESSAGES() {
    for(int i = 0;i < MESSAGE_LEN;i++) {
        MESSAGES[i] = '\0';
    }
}


void encrypto_messages(char file_message[],char file_ciphertext[]) {
    randombytes_buf(nonce, sizeof nonce);
    //loadAndWriteNonce((char*)"nonce.txt",'w');
    FILE *inp = fopen(file_message,"rb");
    FILE *out = fopen(file_ciphertext,"wb");
    if(inp == NULL || out == NULL) {
        printf("\nCan't not encrypto");
        exit(EXIT_FAILURE);
    }
    fwrite(nonce,1,NONCE_LEN,out);
    //printf("\nnonce is: %d",(int)NONCE_LEN);
    if (crypto_aead_aes256gcm_is_available() == 0) {
                abort(); /* Not available on this CPU */
    }
    if(crypto_scalarmult(sharesKey25519,secretKey25519,publicKey25519) != 0) {
            printf("\nCan't caculation share key");
            exit(EXIT_FAILURE);
    }

    unsigned long long CIPHERTEXT_LEN;
    int index = 0;
    while(index = fread(MESSAGES,1,MESSAGE_LEN,inp) != 0){
        if(crypto_aead_aes256gcm_encrypt(CIPHERTEXT,&CIPHERTEXT_LEN,MESSAGES,
                                    MESSAGE_LEN, NULL,0,NULL,nonce,sharesKey25519) != 0){
                printf("\nEncrypto Fail");
                exit(EXIT_FAILURE);
        }
        fwrite(CIPHERTEXT,1,CIPHERTEXT_LEN,out);
        clearMESSAGES();
    }
    fclose(inp);
    fclose(out);
}

void decrypto_messages(char file_ciphertext[],char file_message[]) {

    FILE *inp = fopen(file_ciphertext,"rb");
    FILE *out = fopen(file_message,"w");
    if(inp == NULL || out == NULL) {
        printf("\nCan't decrypto ciphertext");
        exit(EXIT_FAILURE);
    }

    if (crypto_aead_aes256gcm_is_available() == 0) {
                abort(); /* Not available on this CPU */
    }

    if(crypto_scalarmult(sharesKey25519,secretKey25519,publicKey25519) != 0) {
            printf("\nCan't caculation share key");
            exit(EXIT_FAILURE);
    }
    char c;
    int index = 0;
    unsigned long long len;

   /*
   * read nonce into file cipher_text
   */
    int size = fread(nonce,1,NONCE_LEN,inp);
    if(size != (int)NONCE_LEN) {
        printf("\nNonce not correct, size is: %d",size);
        exit(EXIT_FAILURE);
    }

    while(fread(CIPHERTEXT,1,CIPHERTEXT_LEN_MESSAGE,inp) == (int)CIPHERTEXT_LEN_MESSAGE) {
        if(crypto_aead_aes256gcm_decrypt(MESSAGES,&len,
                    NULL,CIPHERTEXT,CIPHERTEXT_LEN_MESSAGE,NULL,0,nonce,sharesKey25519)!=0
                                    || CIPHERTEXT_LEN_MESSAGE < crypto_aead_aes256gcm_KEYBYTES) {
            printf("\nMessages is forged???");
        }else {
            for(int i = 0;i < MESSAGE_LEN;i++) {
                if(MESSAGES[i] != '\0')
                    fprintf(out,"%c",MESSAGES[i]);
            }
        }
    }
    fclose(inp);
    fclose(out);
}


int main(int argc,char **argv) {

    if(sodium_init() == -1) {
        return 1;
    }
    /*char file_one[] = "Alice";
    char file_two[] = "Alice.pub";
    char file_three[] = "Bob";
    char file_four[] = "Bob.pub";
    char out[] = "out.txt";*/
    //createPublicKeyAndSecretKey(file_three ,file_four);
    //loadPublicKeyOfPartnerAndMySecretKey(file_two,file_three);
    //loadPublicKeyOfPartnerAndMySecretKey(file_four,file_one);
    //decrypto_messages(out,(char*)"mess.txt");
    //encrypto_messages((char*)"messages.txt",(char*)"out.txt");
    //char file_mess[] = "mess.txt";
   // char filename[] ="messages.txt";
    //char fileout[] = "out.txt";
    //loadPublicKeyOfPartnerAndMySecretKey((char*)"Bob.pub",(char*)"Alice");
    //encrypto_messages(filename,fileout);
    //decrypto_messages(fileout,file_mess);*/
    if(strcmp(argv[1],"-genkey") == 0) {
        printf("\n-genkey");
        if(argv[2] == 0 || argv[3] == 0){
            //printf("\ncase genkey\n");
            createPublicKeyAndSecretKey((char*)"secretKey",(char*)"publicKey.pub");
        }else {
            createPublicKeyAndSecretKey(argv[2],argv[3]);
        }
    }else if(strcmp(argv[1],"-en") == 0) {
        printf("\n-encrypto");
        if(argv[2] == 0){
            printf("\nPlease enter message need encryption");
        }else {
            if(argv[3] != 0) {
                if(argv[4] == 0) {
                    loadPublicKeyOfPartnerAndMySecretKey(argv[3],(char*)"secretKey");
                    encrypto_messages(argv[2],(char*)"ciphertext.txt");
                }else {
                    loadPublicKeyOfPartnerAndMySecretKey(argv[3],argv[4]);
                    if(argv[5] != 0) {
                        encrypto_messages(argv[2],argv[5]);
                    }else {
                        encrypto_messages(argv[2],(char*)"ciphertext.txt");
                    }
                }
            }else {
                printf("\nPlease enter file contain secretkey and publickey of partner");
            }
        }
    }else if(strcmp(argv[1],"-de") == 0) {
        printf("\n-decrypto");
        if(argv[2] == 0){
            printf("\nPlease enter ciphertex need decryption");
        }else {
            if(argv[3] != 0) {
                if(argv[4] == 0) {
                    loadPublicKeyOfPartnerAndMySecretKey(argv[3],(char*)"secretKey");
                    decrypto_messages(argv[2],(char*)"messages_text.txt");
                }else {
                    loadPublicKeyOfPartnerAndMySecretKey(argv[3],argv[4]);
                    if(argv[5] != 0) {
                        decrypto_messages(argv[2],argv[5]);
                    }else {
                        decrypto_messages(argv[2],(char*)"messages_text.txt");
                    }
                }
            }else {
                printf("\nPlease enter file contain secretkey and publickey of partner");
            }
        }
    }else {
        printf("\nNo Have Option %s",argv[1]);
        printf("\nPlease choose a into -options: -genkey, -en, -de");
    }

}
