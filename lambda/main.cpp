#include <aws/lambda-runtime/runtime.h>
#include <aws/core/utils/json/JsonSerializer.h>

#include <cryptopp/base64.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/twofish.h>

#include <zlib.h>

#include <re2/re2.h>

namespace pka2xml {

std::string compress(const unsigned char* data, int nbytes) {
  unsigned long len = nbytes + nbytes / 100 + 13;

  std::vector<unsigned char> buf(len);

  buf.resize(len + 4);

  int res = ::compress2(buf.data() + 4, &len, data, nbytes, -1);
  if (res != Z_OK) throw res;

  // need to shrink buffer to appropriate size after compression
  buf.resize(len + 4);

  buf[0] = (nbytes & 0xff000000) >> 24;
  buf[1] = (nbytes & 0x00ff0000) >> 16;
  buf[2] = (nbytes & 0x0000ff00) >> 8;
  buf[3] = (nbytes & 0x000000ff);

  return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());
}

std::string uncompress(const unsigned char* data, int nbytes) {
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

std::string uncompress(const unsigned char* data, int nbytes, unsigned long len) {
  std::vector<unsigned char> buf(len);

  int res = ::uncompress(buf.data(), &len, data, nbytes);

  if (res != Z_OK) {
    throw res;
  }

  return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());
}

std::string decrypt(const std::string &input, bool skip_decompression = false) {
  static const unsigned char key[16] = { 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137 };
  static const unsigned char iv[16]  = { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

  typename CryptoPP::EAX<CryptoPP::Twofish>::Decryption d;
  d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

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

  if (skip_decompression) {
    return std::string(output.data() + 4, output.size() - 4);
  } else {
    return uncompress(reinterpret_cast<const unsigned char*>(output.data()), output.size());
  }
}

std::string decrypt_old(std::string input) {
  for (int i = 0; i < input.size(); i++) {
    input[i] = input[i] ^ (input.size() - i);
  }

  return uncompress(reinterpret_cast<const unsigned char*>(input.data()), input.size());
}

std::string encrypt(const std::string &input) {
  static const unsigned char key[16] = { 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137 };
  static const unsigned char iv[16]  = { 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

  typename CryptoPP::EAX<CryptoPP::Twofish>::Encryption e;
  e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

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

} // namespace pka2xml

using namespace aws::lambda_runtime;
using namespace Aws::Utils::Json;

std::string retrofit(const std::string &file) {
  std::string decoded, result;

  CryptoPP::StringSource(file, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  auto decrypted = pka2xml::decrypt(decoded);
  re2::RE2::GlobalReplace(&decrypted, R"(<VERSION>\d\.\d\.\d\.\d{4}</VERSION>)", "<VERSION>6.0.1.0000</VERSION>");
  re2::RE2::GlobalReplace(&decrypted, "<ADDITIONAL_INFO>(.*?)</ADDITIONAL_INFO>", "<ADDITIONAL_INFO>this pka has been altered by github.com/mircodezorzi/pka2xml</ADDITIONAL_INFO>");
  auto encrypted = pka2xml::encrypt(decrypted);

  CryptoPP::StringSource(encrypted, true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), false));

  return result;
}

std::string renew(const std::string &file) {
  std::string decoded, result;

  CryptoPP::StringSource(file, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  auto decrypted = pka2xml::decrypt_old(decoded);
  re2::RE2::GlobalReplace(&decrypted, R"(<VERSION>\d\.\d\.\d\.\d{4}</VERSION>)", "<VERSION>6.0.1.0000</VERSION>");
  re2::RE2::GlobalReplace(&decrypted, "<ADDITIONAL_INFO>(.*?)</ADDITIONAL_INFO>", "<ADDITIONAL_INFO>this pka has been altered by github.com/mircodezorzi/pka2xml</ADDITIONAL_INFO>");
  auto encrypted = pka2xml::encrypt(decrypted);

  CryptoPP::StringSource(encrypted, true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), false));

  return result;
}

std::string decode(const std::string &file) {
  std::string decoded, result;

  CryptoPP::StringSource(file, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  auto decrypted = pka2xml::decrypt(decoded, /* skip_decompression */ true);

  CryptoPP::StringSource(decrypted, true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), /* newline */ false));

  return result;
}

std::string encode(const std::string &file, unsigned long length) {
  std::string decoded, result;

  CryptoPP::StringSource(file, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  // multilying the original length by 2 fixes a segfault
  auto uncompressed = pka2xml::uncompress(reinterpret_cast<const unsigned char*>(decoded.data()), decoded.size(), length * 2);

  re2::RE2::GlobalReplace(&uncompressed, "<ADDITIONAL_INFO>(.*?)</ADDITIONAL_INFO>", "<ADDITIONAL_INFO>this pka has been altered by github.com/mircodezorzi/pka2xml</ADDITIONAL_INFO>");

  auto decrypted = pka2xml::encrypt(uncompressed);

  CryptoPP::StringSource(decrypted, true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), false));

  return result;
}


invocation_response handler(invocation_request const& request) {
  JsonValue json(request.payload);

  if (!json.WasParseSuccessful()) {
    return invocation_response::failure("error while parsing the json request", "InvalidJSON");
  }

  auto v = json.View();

  if (!v.ValueExists("file") || !v.GetObject("file").IsString()) {
    return invocation_response::failure("missing file", "MissingFile");
  }

  if (!v.ValueExists("action") || !v.GetObject("action").IsString()) {
    return invocation_response::failure("missing action", "MissingAction");
  }

  auto file = v.GetString("file");
  file.replace(0, file.find(",") + 1, "");

  auto action = v.GetString("action");

  try {
    if (action == "retrofit") {
      return invocation_response::success(retrofit(file), "data:text/plain;base64");
    } else if (action == "decode") {
      return invocation_response::success(decode(file), "data:text/plain;base64");
    } else if (action == "encode") {
      if (!v.ValueExists("length") || !v.GetObject("length").IsIntegerType()) {
        return invocation_response::failure("missing length", "Missinglength");
      }
      unsigned long length = v.GetInt64("length");
      return invocation_response::success(encode(file, length), "data:text/plain;base64");
    } else if (action == "renew") {
      return invocation_response::success(renew(file), "data:text/plain;base64");
    }
  } catch (const std::exception &e) {
    return invocation_response::failure("error during the decoding of the file", "InvalidPK");
  }

  return invocation_response::failure("action not supported yet", "InvalidAction");
}

int main() {
  run_handler(handler);
  return 0;
}
