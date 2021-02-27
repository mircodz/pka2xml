#include <aws/lambda-runtime/runtime.h>
#include <aws/core/utils/json/JsonSerializer.h>

#include "../include/pka2xml.hpp"

using namespace aws::lambda_runtime;
using namespace Aws::Utils::Json;

// What a fucking mess...

/// \brief Skip compression.
std::string decrypt_compress(const std::string &input) {
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

	return std::string(output.data() + 4, output.size() - 4);
}

std::string uncompress(const unsigned char* data, int nbytes, unsigned long len)
{
  std::vector<unsigned char> buf(len);

	for (;;) {
		int res = ::uncompress(buf.data(), &len, data, nbytes);

		switch (res) {
		case Z_OK:
			return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());

		case Z_MEM_ERROR:
		case Z_DATA_ERROR:
			throw res;

		case Z_BUF_ERROR:
			len *= 2;
			buf.resize(len);
			continue;
		}
	}
}

std::string retrofit(const std::string &file) {
  std::string decoded, result;

  CryptoPP::StringSource(file, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

	// we won't use pka2xml::fix as we want to include our signature
  std::string clear = pka2xml::is_old_pt(decoded) 
		? pka2xml::decrypt_old(decoded)
		: pka2xml::decrypt_pka(decoded);

  re2::RE2::GlobalReplace(&clear, R"(<VERSION>\d\.\d\.\d\.\d{4}</VERSION>)", "<VERSION>6.0.1.0000</VERSION>");
  re2::RE2::GlobalReplace(&clear, "<ADDITIONAL_INFO>(.*?)</ADDITIONAL_INFO>", "<ADDITIONAL_INFO>this pka has been altered by github.com/mircodezorzi/pka2xml</ADDITIONAL_INFO>");

	clear = pka2xml::encrypt_pka(clear);

  CryptoPP::StringSource(clear, true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), false));

  return result;
}

std::string decode(const std::string &file) {
  std::string decoded, result;

  CryptoPP::StringSource(file, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  auto decrypted = decrypt_compress(decoded);

  CryptoPP::StringSource(decrypted, true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result), /* newline */ false));

  return result;
}

std::string encode(const std::string &file, unsigned long length) {
  std::string decoded, result;

  CryptoPP::StringSource(file, true,
    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  auto uncompressed = uncompress(reinterpret_cast<const unsigned char*>(decoded.data()), decoded.size(), length);

  re2::RE2::GlobalReplace(&uncompressed, "<ADDITIONAL_INFO>(.*?)</ADDITIONAL_INFO>", "<ADDITIONAL_INFO>this pka has been altered by github.com/mircodezorzi/pka2xml</ADDITIONAL_INFO>");

  auto decrypted = pka2xml::encrypt_pka(uncompressed);

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
