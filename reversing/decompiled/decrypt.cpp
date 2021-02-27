_QWORD *__fastcall Util::decrypt<CryptoPP::Twofish>(_QWORD *a1, __int64 *a2, unsigned __int8 key_value, unsigned __int8 iv_value)
{
  __int64 v5; // rax
  unsigned int length; // ebx
  int i; // ebp
  __int64 offset; // rdx
  __int64 v10; // rcx
  char v11; // bl
  _QWORD *result; // rax
  __int64 data; // [rsp+10h] [rbp-78h] MAPDST
  _QWORD *v15; // [rsp+18h] [rbp-70h]
  char key; // [rsp+20h] [rbp-68h]
  char iv; // [rsp+30h] [rbp-58h]
  unsigned __int64 v18; // [rsp+48h] [rbp-40h]

  v18 = __readfsqword(0x28u);
  QByteArray::QByteArray(&data, *(*a2 + 4), 0);
  v5 = *a2;
  length = *(*a2 + 4);
  if ( length )
  {
    i = 0;
    do
    {
      v11 = *(*(v5 + 16) + v5 + (length + ~i)) ^ (length - i * length);// v11 = data[data_ptr - i] ^ (length - i * length)
      if ( i < *(data + 4) )
      {
        if ( *data <= 1u )
        {
          offset = *(data + 16);
          if ( offset == 24 )
            goto LABEL_6;
        }
        QByteArray::reallocData(&data, (*(data + 4) + 1), *(data + 11) >> 31);
      }
      else
      {
        QByteArray::expand(&data, i);
      }
      offset = *(data + 16);
LABEL_6:
      v10 = i++;
      *(offset + data + v10) = v11;             // out[i + 1] = v11
      v5 = *a2;
      length = *(*a2 + 4);
    }
    while ( length > i );
  }
  memset_s(&key, 16LL, key_value, 16LL);        // 137
  memset_s(&iv, 16LL, iv_value, 16LL);          // 16
  Util::decipher<CryptoPP::Twofish>(&v15, &data, &key, &iv);
  *a1 = v15;
  v15 = QArrayData::shared_null;
  QByteArray::~QByteArray(&v15);
  QByteArray::~QByteArray(&data);
  while ( 1 )
  {
    result = a1;
    if ( __readfsqword(0x28u) == v18 )
      break;
    __cxa_begin_catch(a1);
    *a1 = QArrayData::shared_null;
    __cxa_end_catch(a1);
  }
  return result;
}
