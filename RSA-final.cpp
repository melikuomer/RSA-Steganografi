#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>
#pragma warning(disable: 4996)
#include <string>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include <fstream>
#include <sstream>
#include <string.h>
#include <windows.h>
#include <bitset>
#include <iomanip>


void generate_rsa_keypair(int key_size, const char* public_key_file, const char* private_key_file)
{
    RSA* rsa_keypair = RSA_new();
    BIGNUM* bne = BN_new();
    int bits = key_size;
    unsigned long e = RSA_F4;

    BN_set_word(bne, e);
    RSA_generate_key_ex(rsa_keypair, bits, bne, NULL);

    FILE* public_file = fopen(public_key_file, "w");
    PEM_write_RSA_PUBKEY(public_file, rsa_keypair);
    fclose(public_file);

    FILE* private_file = fopen(private_key_file, "w");
    PEM_write_RSAPrivateKey(private_file, rsa_keypair, NULL, NULL, 0, NULL, NULL);
    fclose(private_file);

    RSA_free(rsa_keypair);
    BN_free(bne);
}

int rsa_encrypt(const char* public_key_file, const std::string& plaintext, const char* encrypted_file, unsigned char* &chipertext)
{
    std::cout << "Sifreleme islemi basladi" << std::endl;
    FILE* key_file = fopen(public_key_file, "r");
    RSA* rsa_public_key = PEM_read_RSA_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);

    int rsa_size = RSA_size(rsa_public_key);
    unsigned char* encrypted_data = new unsigned char[rsa_size];
    int encrypted_length = RSA_public_encrypt(plaintext.length(), reinterpret_cast<const unsigned char*>(plaintext.c_str()),
        encrypted_data, rsa_public_key, RSA_PKCS1_PADDING);

    std::ofstream outfile(encrypted_file, std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(encrypted_data), encrypted_length);
    outfile.close();

    RSA_free(rsa_public_key);
    //delete[] encrypted_data;
    chipertext = encrypted_data;
    return encrypted_length;
}

unsigned char* rsa_decrypt(const char* private_key_file, unsigned char* encrypted_file, const char* decrypted_file)
{
    FILE* key_file = fopen(private_key_file, "r");
    RSA* rsa_private_key = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    //std::ifstream encrypted_input(encrypted_file, std::ios::binary);
    //std::ostringstream encrypted_buffer;
    //encrypted_buffer << encrypted_input.rdbuf();
    //std::string ciphertext = encrypted_buffer.str();
    //encrypted_input.close();

    int rsa_size = RSA_size(rsa_private_key);
    unsigned char* decrypted_data = new unsigned char[rsa_size];
    int decrypted_length = RSA_private_decrypt(256, reinterpret_cast<const unsigned char*>(encrypted_file),
        decrypted_data, rsa_private_key, RSA_PKCS1_PADDING);

    std::ofstream decrypted_output(decrypted_file);
    decrypted_output.write(reinterpret_cast<const char*>(decrypted_data), decrypted_length);
    decrypted_output.close();

    RSA_free(rsa_private_key);
    //delete[] decrypted_data;
    return decrypted_data;
}


using namespace std;


std::string toBinary(unsigned const char* str, int size);
char strToChar(string str);
unsigned char* toString(string binaryText);
//std::string embedMessage(string fileName, string outFileName, string message);
//std::string getMessage(string fileName);

void embedMessage(string fileName, string outFileName, unsigned char* message , int message_size, string outstring)

std::string embedMessage(string fileName, string outFileName, unsigned char* message , int message_size) {
    ifstream pngFile;
    pngFile.open(fileName, ios::in | ios::binary);
    unsigned char header[54];
    pngFile.read((char*)header, sizeof(header));
    int width = *(int*)&header[18];
    int height = *(int*)&header[22];
    cout << "Girdiginiz Resmin Cozunurlugu: " << width << 'x' << height << endl;

    cout << "Resime mesaj gomme islemi basladi" << endl;

    string secret = toBinary(message , message_size);
    cout << "Resime Yazilacak Binary Mesaj:  " << secret << endl;

   
    if (pngFile)
    {
        pngFile.seekg(54, ios_base::beg);
        int secret_cursor = 0;

        ofstream outputStream;
        outputStream.open(outFileName, ios::out | ios::binary);
        outputStream.write((char*)&header, sizeof(header));
        //outputStream.seekp();

        int index = 0;
        while (pngFile.good() && !pngFile.eof())
        {
            if (index > width * height * 3) {
                char x;
                pngFile.read(&x, sizeof(x));
                outputStream.write(&x, sizeof(x));
                continue;
            }
            unsigned char buffer[3];


            pngFile.read((char*)&buffer, sizeof(buffer));


            for (int i = 0; i < 3; i++) {

                unsigned char temp = buffer[i];
                char LSB = (temp % 2 == 1) ? '1' : '0';
                //cout<< LSB;
                if (secret_cursor >= secret.length()) {
                    if (LSB != '1') {
                        buffer[i] += 1;
                    }
                }
                else if (LSB != secret[secret_cursor]) {
                    buffer[i] += 1;
                }
                else {

                }

                secret_cursor++;
            }


            outputStream.write((char*)&buffer, sizeof(buffer));

        }
        cout << "Dosya Basari Ile Olusturuldu. Dosya Adi: " << outFileName << endl;
        pngFile.close();
        outputStream.close();

    }
    return "Tum Islemler Basarili ";
}
unsigned char* getMessage(string fileName) {
    ifstream file;
    file.open(fileName, ios::in | ios::binary);
    unsigned char header[54];
    file.read((char*)header, sizeof(header));
    int width = *(int*)&header[18];
    int height = *(int*)&header[22];
    file.seekg(54, ios_base::beg);
    string secret = "";
    cout << "Resmin cozunurlugu: " << width << 'x' << height << endl;
    if (file)
    {
        int index = 0;
        while (file.good() && !file.eof() && index < 2048)
        {
            unsigned char buffer[4];


            file.read((char*)&buffer, sizeof(buffer));

            for (int i = 0; i < 4; i++) {
                unsigned char temp = buffer[i];
                int LSB = temp % 2;

                if (LSB == 0) {
                    secret += "0";
                }
                else secret += "1";
                index++;
            }




        }
        file.close();
        cout << "Okunan Binary Mesaj: " << secret << endl;

    }
    return toString(secret);
}



std::string toBinary(unsigned const char* str, int size) {
    
    std::string binary = "";
    for (int i = 0; i < size; i++) {
       // cout << i << endl;
        binary += std::bitset<8>(str[i]).to_string();
    }
    return binary;
}
unsigned char* toString(string binaryText) {
    //string result = "";
    //cout <<"abi: " << binaryText;
    unsigned char* result = new unsigned char[256];
    for (int i = 0; i < binaryText.length(); i += 8) {
        //cout<< binaryText.length();
        string text = binaryText.substr(i, 8);
        result[i/8] = strToChar(text);
    }
    
    return result;
}
char strToChar(string str) {
    char parsed = 0;
    for (int i = 0; i < 8; i++) {
        if (str[i] == '1') {
            parsed |= 1 << (7 - i);
        }
    }
    return parsed;
}








int main(int argc, char** argv) {
    if (argc == 2) {
        unsigned char* cipherText = getMessage(argv[1]);
        std::cout << "Resimden Okunan Sifrelenmis Mesaj: ";
        for (int i = 0; i < 256; i++) {
            std::cout << cipherText[i];
        }
        std::cout << endl;
        unsigned char* result = rsa_decrypt("private.pem", cipherText, "decrypted.txt");
        
        std::cout << "Resimden Okunan Mesaj: ";
        for (int i = 0; i < 256; i++) {
            std::cout << result[i];
        }
        std::cout << endl;

        //cout << getMessage();
    }
    else if (argc == 4) {
        string inputfile = argv[1];
        string outputfile = argv[2];
        string message = argv[3];
        unsigned char* encrypted_message ;
        int message_size;
        message_size = rsa_encrypt("public.pem", message, "encrypted.txt", encrypted_message);

        cout << "Girdiginiz Mesaj: " << message << endl;
        cout << "Mesajin sifrelenmis hali: ";
        //std::cout << "Resimden Okunan Mesaj: ";
        for (int i = 0; i < message_size; i++) {
            std::cout << encrypted_message[i];
        }
        cout << endl;
        cout << embedMessage(argv[1], argv[2], encrypted_message, message_size) <<endl;
    }
    else if (argc ==1)
    {
        std::cout << "Sifre olusturuldu public.pem private.pem" << std::endl;
        generate_rsa_keypair(2048, "public.pem", "private.pem");
        //unsigned char* chipertext = getMessage("output.bmp");
        //std::cout << "Resimden Okunan Mesaj: " << rsa_decrypt("private.pem", chipertext, "decrypted.txt") << endl;
        //cout <<getMessage("worked.bmp");
        return 0;

    }
    else {
        std::cout << "Yanlis kullanim.\n Secenekler: \n *.exe <girdi dosya adi> <cikti dosya adi> <mesaj> (sifreleme)"
            << "\n *.exe <dosya adi> (desifreleme islemi) \n *.exe (parametre olmadan) (anahtar uretme)";
    }

    return 0;


}