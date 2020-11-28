#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/twofish.h>

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

  std::string processed;
  std::string output;

  // Stage 1 - deobfuscation
  int length = input.size();
  for (int i = 0; i < input.size(); i++) {
    processed += input[length + ~i] ^ (length - i * length);
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
std::string decrypt_pt(const std::string &input) {
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

bool opt_exists(char** begin, char** end, const std::string& option) {
    return std::find(begin, end, option) != end;
}

int main(int argc, char *argv[]) {

  if (argc > 3 && opt_exists(argv, argv + argc, "-p")) {
    std::ifstream f_in{argv[2]};
    if (!f_in.is_open()) {
      throw 0;
    }
    std::string input{std::istreambuf_iterator<char>(f_in),
                      std::istreambuf_iterator<char>()};
    f_in.close();

    std::ofstream f_out{argv[3]};
    if (!f_out.is_open()) {
      throw 0;
    }
    f_out << decrypt_pt(input);
    f_out.close();
  } else if (argc > 2 && opt_exists(argv, argv + argc, "-l")) {
    std::ifstream f_in{argv[2]};
    if (!f_in.is_open()) {
      throw 0;
    }
    std::string line;
    while (std::getline(f_in, line)) {
      std::cout << decrypt_logs(line) << std::endl;
    }
    f_in.close();
  } else if (argc > 2 && opt_exists(argv, argv + argc, "-n")) {
    std::ifstream f_in{argv[2]};
    if (!f_in.is_open()) {
      throw 0;
    }
    std::string input{std::istreambuf_iterator<char>(f_in),
                      std::istreambuf_iterator<char>()};
    std::cout << decrypt_nets(input) << std::endl;
    f_in.close();
  }

}
