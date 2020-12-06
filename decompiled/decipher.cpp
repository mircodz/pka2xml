QByteArray *__fastcall Util::decipher<CryptoPP::Twofish>(QByteArray *a1, __int64 a2, const unsigned __int8 *key, const unsigned __int8 *iv)
{
  CryptoPP::Algorithm *sink; // r13
  __int64 filter; // r14
  char *v8; // rsi
  char *v10; // [rsp+10h] [rbp-12E8h]
  int v11[2]; // [rsp+18h] [rbp-12E0h]
  char v12; // [rsp+20h] [rbp-12D8h]
  __int64 *stringsource; // [rsp+30h] [rbp-12C8h]
  __int64 *v14; // [rsp+38h] [rbp-12C0h]
  __int64 v15; // [rsp+48h] [rbp-12B0h]
  __int64 *decryptor; // [rsp+A0h] [rbp-1258h]
  __int64 *v17; // [rsp+A8h] [rbp-1250h]
  __int64 *v18; // [rsp+B0h] [rbp-1248h]
  __int64 *v19; // [rsp+188h] [rbp-1170h]
  __int64 *v20; // [rsp+190h] [rbp-1168h]
  __int64 v21; // [rsp+1A0h] [rbp-1158h]
  __int64 v22; // [rsp+1A8h] [rbp-1150h]
  __int64 v23; // [rsp+1B0h] [rbp-1148h]
  int v24; // [rsp+1B8h] [rbp-1140h]
  __int64 *v25; // [rsp+1C0h] [rbp-1138h]
  __int64 *v26; // [rsp+1C8h] [rbp-1130h]
  __int64 v27; // [rsp+1D0h] [rbp-1128h]
  char v28; // [rsp+271h] [rbp-1087h]
  __int64 v29; // [rsp+278h] [rbp-1080h]
  __int64 v30; // [rsp+280h] [rbp-1078h]
  __int64 *input; // [rsp+288h] [rbp-1070h]
  __int64 v32; // [rsp+290h] [rbp-1068h]
  char v33; // [rsp+1291h] [rbp-67h]
  __int64 v34; // [rsp+1298h] [rbp-60h]
  __int64 v35; // [rsp+12A0h] [rbp-58h]
  __int64 *v36; // [rsp+12A8h] [rbp-50h]
  unsigned __int64 v37; // [rsp+12B8h] [rbp-40h]

  v37 = __readfsqword(0x28u);
  *v11 = 0LL;
  v12 = 0;
  v10 = &v12;
  CryptoPP::EAX_Base::EAX_Base(&decryptor);
  decryptor = &`vtable for'CryptoPP::EAX_Final<CryptoPP::Twofish,false> + 2;
  v17 = &`vtable for'CryptoPP::EAX_Final<CryptoPP::Twofish,false> + 48;
  v18 = &`vtable for'CryptoPP::EAX_Final<CryptoPP::Twofish,false> + 70;
  v19 = &`vtable for'CryptoPP::SimpleKeyingInterface + 2;
  CryptoPP::Algorithm::Algorithm(&v20, 1);
  v21 = -1LL;
  v22 = 0LL;
  v23 = 0LL;
  v24 = 0;
  v20 = &`vtable for'CryptoPP::CMAC<CryptoPP::Twofish> + 28;
  v19 = &`vtable for'CryptoPP::CMAC<CryptoPP::Twofish> + 2;
  v25 = &`vtable for'CryptoPP::SimpleKeyingInterface + 2;
  CryptoPP::Algorithm::Algorithm(&v26, 1);
  v29 = 0x3FFFFFFFFFFFFFFFLL;
  v34 = 0x3FFFFFFFFFFFFFFFLL;
  input = &v27;
  v36 = &v32;
  v30 = 40LL;
  v28 = 1;
  v35 = 1024LL;
  v33 = 1;
  v26 = &`vtable for'CryptoPP::BlockCipherFinal<(CryptoPP::CipherDir)0,CryptoPP::Twofish::Enc> + 25;
  v25 = &`vtable for'CryptoPP::BlockCipherFinal<(CryptoPP::CipherDir)0,CryptoPP::Twofish::Enc> + 2;
  CryptoPP::SimpleKeyingInterface::SetKeyWithIV(&decryptor, key, 16uLL, iv, 16uLL);// *key, key_length, *iv, iv_length
  sink = operator new(0x20uLL);
  CryptoPP::Algorithm::Algorithm(sink, 0);
  *(sink + 3) = &v10;
  *(sink + 1) = &`vtable for'CryptoPP::StringSinkTemplate<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>> + 52;
  *sink = &`vtable for'CryptoPP::StringSinkTemplate<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>> + 2;
  filter = operator new(0x230uLL);
  CryptoPP::AuthenticatedDecryptionFilter::AuthenticatedDecryptionFilter(
    filter,
    &decryptor,
    sink,
    16LL,                                       // throw on error (default)
    0xFFFFFFFFLL,                               // default
    5LL);                                       // padding (default)
  CryptoPP::StringSource::StringSource(         // StringSource (const byte *string, unsigned int length, bool pumpAll, BufferedTransformation *attachment=NULL)
    &stringsource,
    *(*a2 + 16LL) + *a2,                        // source, second argument of function
    *(*a2 + 4LL),                               // length
    1LL,                                        // pumpAll
    filter);
  v14 = &`vtable for'CryptoPP::Filter + 55;
  stringsource = &`vtable for'CryptoPP::Filter + 2;
  if ( v15 )
    (*(*v15 + 8LL))();
  v8 = v10;
  QByteArray::QByteArray(a1, v10, v11[0]);
  decryptor = &`vtable for'CryptoPP::EAX_Final<CryptoPP::Twofish,false> + 2;
  v17 = &`vtable for'CryptoPP::EAX_Final<CryptoPP::Twofish,false> + 48;
  v18 = &`vtable for'CryptoPP::EAX_Final<CryptoPP::Twofish,false> + 70;
  CryptoPP::CMAC<CryptoPP::Twofish>::~CMAC(&v19, v8);
  CryptoPP::EAX_Base::~EAX_Base(&decryptor);
  if ( v10 != &v12 )
    operator delete(v10);
  return a1;
}
