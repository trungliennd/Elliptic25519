#include<stdint.h>
#include<stdlib.h>
#include<iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
using namespace std;

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(unsigned char c) {

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

string base64_encode( const string &str ){

    BIO *base64_filter = BIO_new( BIO_f_base64() );
    BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );

    BIO *bio = BIO_new( BIO_s_mem() );
    BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL );

    bio = BIO_push( base64_filter, bio );

    BIO_write( bio, str.c_str(), str.length() );

    BIO_flush( bio );

    char *new_data;

    long bytes_written = BIO_get_mem_data( bio, &new_data );

    string result( new_data, bytes_written );
    BIO_free_all( bio );

    return result;

}



string base64_decode(string &str ){

    BIO *bio, *base64_filter, *bio_out;
    char inbuf[512];
    int inlen;
    base64_filter = BIO_new( BIO_f_base64() );
    BIO_set_flags( base64_filter, BIO_FLAGS_BASE64_NO_NL );

    bio = BIO_new_mem_buf( (void*)str.c_str(), str.length() );

    bio = BIO_push( base64_filter, bio );

    bio_out = BIO_new( BIO_s_mem() );

    while( (inlen = BIO_read(bio, inbuf, 512)) > 0 ){
        BIO_write( bio_out, inbuf, inlen );
    }

    BIO_flush( bio_out );

    char *new_data;
    long bytes_written = BIO_get_mem_data( bio_out, &new_data );

    string result( new_data, bytes_written );

    BIO_free_all( bio );
    BIO_free_all( bio_out );

    return result;

}

