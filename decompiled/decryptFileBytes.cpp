unsigned __int64 __fastcall Util::decryptFileBytes(const QByteArray *original, QByteArray *a2)
{
  QByteArray *v2; // rbx
  __int64 v5; // rdx
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v12; // [rsp+0h] [rbp-68h]
  volatile signed __int32 *v14; // [rsp+10h] [rbp-58h]
  QByteArray *decrypted; // [rsp+18h] [rbp-50h] MAPDST
  unsigned __int8 plain[8]; // [rsp+20h] [rbp-48h]
  unsigned __int64 v17; // [rsp+28h] [rbp-40h]

  v2 = a2;
  v17 = __readfsqword(0x28u);
  QDomDocument::QDomDocument(&v12);
  if ( QDomDocument::setContent(&v12, original, 0LL, 0LL, 0LL) )
  {
    QByteArray::operator=(a2, original);
  }
  else
  {
    decrypted = QArrayData::shared_null;
    Util::decryptPTSave(&decrypted, original);  // decrypted = decrypt(original)
    QByteArray::~QByteArray(&decrypted);
    if ( !*(decrypted + 1) )
      QByteArray::operator=(&decrypted, original);
    Util::deobfuscateBytes(&decrypted, original);// decrypted = deobfuscate(decrypted)
    v5 = *(decrypted + 1);
    qUncompress(plain, *(decrypted + 4) + decrypted);// plain = uncompress(decrypted)
    v6 = *v2;
    *v2 = *plain;
    *plain = v6;
    QByteArray::~QByteArray(plain);
    if ( !*(*v2 + 4LL) )
    {
      QByteArray::~QByteArray(&decrypted);
      QDomDocument::~QDomDocument(&v12);
      return __readfsqword(0x28u) ^ v17;
    }
    QString::QString(&decrypted, 4294967170LL);
    QString::QString(&v14, 4294967234LL);
    *plain = v14;
    if ( *v14 < 0xFFFFFFFF && *v14 != 0 )
      _InterlockedAdd(v14, 1u);
    QString::append(plain, &decrypted);
    v7 = QByteArray::replace(v2, plain, &src);
    QByteArray::operator=(v2, v7);
    QString::~QString(plain);
    QString::~QString(&v14);
    QString::~QString(&decrypted);
    QString::QString(&decrypted, 4294967171LL);
    QString::QString(&v14, 4294967235LL);
    *plain = v14;
    if ( *v14 < 0xFFFFFFFF && *v14 != 0 )
      _InterlockedAdd(v14, 1u);
    QString::append(plain, &decrypted);
    v8 = QByteArray::replace(v2, plain, &src);
    QByteArray::operator=(v2, v8);
    QString::~QString(plain);
    QString::~QString(&v14);
    QString::~QString(&decrypted);
    QString::QString(&decrypted, 4294967188LL);
    QString::QString(&v14, 4294967192LL);
    *plain = v14;
    if ( *v14 < 0xFFFFFFFF && *v14 != 0 )
      _InterlockedAdd(v14, 1u);
    QString::append(plain, &decrypted);
    v9 = QByteArray::replace(v2, plain, &src);
    QByteArray::operator=(v2, v9);
    QString::~QString(plain);
    QString::~QString(&v14);
    QString::~QString(&decrypted);
    QString::QString(&decrypted, 4294967186LL);
    QString::QString(&v14, 4294967187LL);
    *plain = v14;
    if ( *v14 < 0xFFFFFFFF && *v14 != 0 )
      _InterlockedAdd(v14, 1u);
    QString::append(plain, &decrypted);
    v10 = QByteArray::replace(v2, plain, "\"");
    QByteArray::operator=(v2, v10);
    QString::~QString(plain);
    QString::~QString(&v14);
    QString::~QString(&decrypted);
    QByteArray::~QByteArray(&decrypted);
  }
  QDomDocument::~QDomDocument(&v12);
  return __readfsqword(0x28u) ^ v17;
}
