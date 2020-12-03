#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/twofish.h>
#include <cryptopp/cast.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <zlib.h>

#include "base64.h"

/// TODO documentation
std::string uncompress(const unsigned char* data, int nbytes) {
  unsigned long len = (data[0] << 24)
        | (data[1] << 16)
        | (data[2] <<  8)
        | (data[3]      );

  std::vector<unsigned char> buf(len);

  int res = uncompress(buf.data(), &len, data + 4, nbytes - 4);

  if (res != Z_OK) {
    throw res;
  }

  return std::string(reinterpret_cast<const char*>(buf.data()));
}

/// TODO documentation
template <typename Algorithm>
std::string decrypt(
    const std::string &input,
    const unsigned char *key,
    int key_size,
    const unsigned char *iv,
    int iv_size,
    bool skip_last_stages = false) {
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

  if (skip_last_stages) {
    return output;
  }

  // Stage 3 - deobfuscation
  for (int i = 0; i < output.size(); i++) {
    output[i] = output[i] ^ (output.size() - i);
  }

  // Stage 4 - decompression
  return uncompress(reinterpret_cast<const unsigned char*>(output.data()), output.size());
}

/// \brief Decrypt Packet Tracer file.
/// \param input Contents of file.
/// \return Decrypted input.
///
/// 1. deobfuscation:
///
///   b[i] = a[l + ~i] ^ (l - i * l)
///
///   where l = length a
///         a = input string
///         b = output string
///
/// 2. decryption: TwoFish in EAX mode with key = { 137 } * 16 and iv = { 16 } * 16
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
std::string decrypt_pka(const std::string &input) {
  static const unsigned char key[16] = { 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137 };
  static const unsigned char iv[16]  = { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

  return decrypt<CryptoPP::Twofish>(input, key, sizeof(key), iv, sizeof(iv));
}

/// TODO documentation
std::string decrypt_logs(const std::string &input) {
  static const unsigned char key[16] = { 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186 };
  static const unsigned char iv[16]  = { 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190 };

  std::string decoded = base64_decode(input);
  return decrypt<CryptoPP::Twofish>(decoded, key, sizeof(key), iv, sizeof(iv), /* skip_last_stages */ true);
}

/// TODO documentation
std::string decrypt_nets(const std::string &input) {
  static const unsigned char key[16] = { 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186 };
  static const unsigned char iv[16]  = { 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190 };

  return decrypt<CryptoPP::Twofish>(input, key, sizeof(key), iv, sizeof(iv), /* skip_last_stages */ true);
}

/// TODO documentation
/// TODO reverse second part of decoding
std::string decrypt_sm(const std::string &input) {
  static const unsigned char key[16] = { 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18 };
  static const unsigned char iv[16]  = { 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254 };

  return decrypt<CryptoPP::CAST256>(input, key, sizeof(key), iv, sizeof(iv), /* skip_last_stages */ true);
}

/// TODO documentation
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

/// TODO documentation
template <typename Algorithm>
std::string encrypt(
    const std::string &input,
    const unsigned char *key,
    int key_size,
    const unsigned char *iv,
    int iv_size) {
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
  std::string output;
  int length = encrypted.size();
  output.resize(length);
  for (int i = 0; i < encrypted.size(); i++) {
    // I lost an entire hour trying to figure out why this wouldn't work.
    output[length + ~i] = encrypted[i] ^ (length - i * length);
  }

  return output;
}

/// \see decrypt_pka
std::string encrypt_pka(const std::string &input) {
  static const unsigned char key[16] = { 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137 };
  static const unsigned char iv[16]  = { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

  return encrypt<CryptoPP::Twofish>(input, key, sizeof(key), iv, sizeof(iv));
}

/// TODO documentation
bool opt_exists(char** begin, char** end, const std::string& option) {
    return std::find(begin, end, option) != end;
}

void die(const char *message) {
  std::fprintf(stderr, "%s", message);
  std::exit(1);
}

void help() {
  std::printf("pka2xml\n");
  std::printf("\t-d decrypt pka to xml\n");
  std::printf("\t-e encrypt xml to pka\n");
  std::printf("\t-nets decrypt packet tracer net file\n");
  std::printf("\t-logs decrypt packet tracer log file\n");
  std::printf("\t-pts  decrypt packet tracer script module (WIP)\n");
  std::exit(1);
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    help();
  }

  // TODO graceful error checking
  try {
    if (argc > 3 && opt_exists(argv, argv + argc, "-d")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in),
                        std::istreambuf_iterator<char>()};
      f_in.close();
      std::ofstream f_out{argv[3]};
      if (!f_out.is_open()) {
        die("error opening file");
      }
      f_out << decrypt_pka(input);
      f_out.close();
    } else if (argc > 3 && opt_exists(argv, argv + argc, "-e")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in),
                        std::istreambuf_iterator<char>()};
      f_in.close();
      std::ofstream f_out{argv[3]};
      if (!f_out.is_open()) {
        die("error opening file");
      }
      f_out << encrypt_pka(input);
      f_out.close();
    } else if (argc > 2 && opt_exists(argv, argv + argc, "-logs")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening file");
      }
      std::string line;
      while (std::getline(f_in, line)) {
        std::cout << decrypt_logs(line) << std::endl;
      }
      f_in.close();
    } else if (argc > 2 && opt_exists(argv, argv + argc, "-nets")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in),
            std::istreambuf_iterator<char>()};
      std::cout << decrypt_nets(input) << std::endl;
      f_in.close();
    } else if (argc > 3 && opt_exists(argv, argv + argc, "-pts")) {
      std::ifstream f_in{argv[2]};
      if (!f_in.is_open()) {
        die("error opening file");
      }
      std::string input{std::istreambuf_iterator<char>(f_in),
                        std::istreambuf_iterator<char>()};
      std::ofstream f_out{argv[3]};
      if (!f_out.is_open()) {
        die("error opening file");
      }
      f_out << decrypt_sm(input);
      f_out.close();
    }
  } catch (int err) {
    die("error");
  }

}
