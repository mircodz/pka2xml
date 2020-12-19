#include <cryptopp/base64.h>
#include <cryptopp/cast.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/twofish.h>

#include <re2/re2.h>

#include <zlib.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace pka2xml
{

/// \brief Uncompress buffer with zlib. Opposite of `compress`.
///
/// First four bytes correspond to the uncompressd output size.
std::string uncompress(const unsigned char* data, int nbytes)
{
  unsigned long len = (data[0] << 24)
                    | (data[1] << 16)
                    | (data[2] <<  8)
                    | (data[3]      );

  std::vector<unsigned char> buf(len);

  int res = ::uncompress(buf.data(), &len, data + 4, nbytes - 4);

  if (res != Z_OK) {
    throw res;
  }

  return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());
}

/// 1. deobfuscation:
///
///   b[i] = a[l + ~i] ^ (l - i * l)
///
///   where l = length a
///         a = input string
///         b = output string
///
/// 2. decryption:
///      - TwoFish in EAX mode with key = { 137 } * 16 and iv = { 16 } * 16
///        in the case of pka/pkt files
///      - Twofish in EAX mode with key = { 186 } * 16 and iv = { 190 } * 16
///        in the case of nets and logs
///      - CAST256 in EAX mode with key = { 18 } * 16 and iv = { 254 } * 16
///        in the case of packet tracer script modules
///
/// 3. deobfuscation
///
///   b[i] = a[l] ^ (l - i)
///
///   where l = length a
///         a = input string
///         b = output string
///
/// 4. decompression: zlib compression
template <typename Algorithm>
std::string decrypt(
    const std::string &input,
    const unsigned char *key, int key_size,
    const unsigned char *iv,  int iv_size)
{
  typename CryptoPP::EAX<Algorithm>::Decryption d;
  d.SetKeyWithIV(key, key_size, iv, iv_size);

  int length = input.size();
  std::string processed(length, '\0');
  std::string output;

  // Stage 1 - deobfuscation
  for (int i = 0; i < length; i++) {
    processed[i] = input[length + ~i] ^ (length - i * length);
  }

  // Stage 2 - decryption
  CryptoPP::StringSource ss(processed, true,
    new CryptoPP::AuthenticatedDecryptionFilter(d, new CryptoPP::StringSink(output))
  );

  // Stage 3 - deobfuscation
  for (int i = 0; i < output.size(); i++) {
    output[i] = output[i] ^ (output.size() - i);
  }

  // Stage 4 - decompression
  return uncompress(reinterpret_cast<const unsigned char*>(output.data()), output.size());
}

/// \brief Similar to `decrypt`, but with only the first two steps.
/// \see decrypt
template <typename Algorithm>
std::string decrypt2(
    const std::string &input,
    const unsigned char *key, int key_size,
    const unsigned char *iv,  int iv_size)
{
  typename CryptoPP::EAX<Algorithm>::Decryption d;
  d.SetKeyWithIV(key, key_size, iv, iv_size);

  int length = input.size();
  std::string processed(length, '\0');
  std::string output;

  // Stage 1 - deobfuscation
  for (int i = 0; i < length; i++) {
    processed[i] = input[length + ~i] ^ (length - i * length);
  }

  // Stage 2 - decryption
  CryptoPP::StringSource ss(processed, true,
    new CryptoPP::AuthenticatedDecryptionFilter(d, new CryptoPP::StringSink(output))
  );

  return output;
}

/// \brief Decrypt Packet Tracer file.
std::string decrypt_pka(const std::string &input)
{
  static const unsigned char key[16] = { 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137 };
  static const unsigned char iv[16]  = { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

  return decrypt<CryptoPP::Twofish>(input, key, sizeof(key), iv, sizeof(iv));
}

std::string decrypt_old(std::string input)
{
	for (int i = 0; i < input.size(); i++) {
		input[i] = input[i] ^ (input.size() - i);
	}

	return uncompress(reinterpret_cast<const unsigned char*>(input.data()), input.size());
}

/// \brief Decrypt logs file.
///
/// Logs file have to be decoded from base64 before being actually decrypted.
std::string decrypt_logs(const std::string &input)
{
  static const unsigned char key[16] = { 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186 };
  static const unsigned char iv[16]  = { 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190 };

  std::string decoded;
  CryptoPP::StringSource ss(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  return decrypt2<CryptoPP::Twofish>(decoded, key, sizeof(key), iv, sizeof(iv));
}

/// \brief Decrypt file $HOME/packettracer/nets.
///
/// Virtually the same encryption method of log files, but without the base64 encoding.
///
/// \see decrypt_logs
std::string decrypt_nets(const std::string &input) {
  static const unsigned char key[16] = { 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186 };
  static const unsigned char iv[16]  = { 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190 };

  return decrypt2<CryptoPP::Twofish>(input, key, sizeof(key), iv, sizeof(iv));
}

/// TODO reverse second part of decoding
std::string decrypt_sm(const std::string &input)
{
  static const unsigned char key[16] = { 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18 };
  static const unsigned char iv[16]  = { 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254 };

  throw std::runtime_error("unimplemented");

  return decrypt2<CryptoPP::CAST256>(input, key, sizeof(key), iv, sizeof(iv));
}

/// \brief Compress buffer with zlib. Oppomise of `uncompress`.
///
/// First four bytes correspond to the uncompressd output size.
std::string compress(const unsigned char* data, int nbytes) {
  unsigned long len = nbytes + nbytes / 100 + 13;

  std::vector<unsigned char> buf(len);

  buf.resize(len + 4);

  int res = ::compress2(buf.data() + 4, &len, data, nbytes, -1);

  if (res != Z_OK) {
    throw res;
  }

  // need to shrink buffer to appropriate size after compression
  buf.resize(len + 4);

  buf[0] = (nbytes & 0xff000000) >> 24;
  buf[1] = (nbytes & 0x00ff0000) >> 16;
  buf[2] = (nbytes & 0x0000ff00) >> 8;
  buf[3] = (nbytes & 0x000000ff);

  return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());
}

/// \see decrypt
template <typename Algorithm>
std::string encrypt(
    const std::string &input,
    const unsigned char *key, int key_size,
    const unsigned char *iv,  int iv_size,
    bool skip_first_stages = false) 
{
  typename CryptoPP::EAX<Algorithm>::Encryption e;
  e.SetKeyWithIV(key, key_size, iv, iv_size);

  // Stage 1 - compression
  std::string compressed = compress(reinterpret_cast<const unsigned char*>(input.data()), input.size());

  // Stage 2 - obfuscation
  for (int i = 0; i < compressed.size(); i++) {
    compressed[i] = compressed[i] ^ (compressed.size() - i);
  }

  // Stage 3 - encryption
  std::string encrypted;
  CryptoPP::StringSource ss(compressed, true,
    new CryptoPP::AuthenticatedEncryptionFilter(e, new CryptoPP::StringSink(encrypted))
  );

  // Stage 4 - obfuscation
  int length = encrypted.size();
  std::string output(length, '\0');
  for (int i = 0; i < encrypted.size(); i++) {
    output[length + ~i] = encrypted[i] ^ (length - i * length);
  }

  return output;
}

/// \brief Similara to encrypt, but skip first two steps
template <typename Algorithm>
std::string encrypt2(
    const std::string &input,
    const unsigned char *key, int key_size,
    const unsigned char *iv,  int iv_size) {
  typename CryptoPP::EAX<Algorithm>::Encryption e;
  e.SetKeyWithIV(key, key_size, iv, iv_size);

  // Skip stage 1 & 2

  // Stage 3 - encryption
  std::string encrypted;
  CryptoPP::StringSource ss(input, true,
    new CryptoPP::AuthenticatedEncryptionFilter(e, new CryptoPP::StringSink(encrypted))
  );

  // Stage 4 - obfuscation
  int length = encrypted.size();
  std::string output(length, '\0');
  for (int i = 0; i < encrypted.size(); i++) {
    output[length + ~i] = encrypted[i] ^ (length - i * length);
  }

  return output;
}

/// \see decrypt_pka
std::string encrypt_pka(const std::string &input) {
  static const unsigned char key[16] = { 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137 };
  static const unsigned char iv[16]  = { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

  return encrypt<CryptoPP::Twofish>(input, key, sizeof(key), iv, sizeof(iv), /* skip_first_stages */ true);
}

/// \see decrypt_nets
std::string encrypt_nets(const std::string &input) {
  static const unsigned char key[16] = { 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186 };
  static const unsigned char iv[16]  = { 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190 };

  return encrypt2<CryptoPP::Twofish>(input, key, sizeof(key), iv, sizeof(iv));
}

/// \brief Check if PT file was emitted from a Packet Tracer version prior to 5.
/// \see uncompress
///
/// Old Packet Tracer simulation files were obfuscated with a two-stage method:
/// First the xml would be compressed with qCompress (which internally uses
/// zlib), and then they would be encryted by xoring each bytes with a value
/// relative to it's position.
///
/// By cheking for the zlib headers in the correct position we can assess with
/// encryption method was used.
bool is_old_pt(const std::string &str)
{
  return (((unsigned char)(str[4] ^ (str.size() - 4)) == 0x78)
       || ((unsigned char)(str[5] ^ (str.size() - 5)) == 0x9C));
}

/// \brief Tweak pka/pkt file so it can be read by any version of Packet Tracer.
/// \see is_old_pt
std::string fix(std::string input) 
{
  std::string clear = is_old_pt(input) 
		? decrypt_old(input)
		: decrypt_pka(input);

  re2::RE2::GlobalReplace(&clear, R"(<VERSION>\d\.\d\.\d\.\d{4}</VERSION>)", "<VERSION>6.0.1.0000</VERSION>");
  return encrypt_pka(clear);
}

} // namespace pka2xml
