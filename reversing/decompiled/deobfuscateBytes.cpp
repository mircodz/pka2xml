QByteArray *__fastcall Util::deobfuscateBytes(QByteArray *a1, QByteArray *unused)
{
  QByteArray *data; // rax
  int length; // edx
  int i; // ebx
  QByteArray *v5; // rdx
  __int64 offset; // rcx
  __int64 v7; // r13
  char v8; // bp

  data = *a1;
  length = *(*a1 + 4LL);
  if ( length )
  {
    i = 0;
    do
    {
      v7 = i;
      offset = *(data + 2);
      v8 = *(data + i + offset) ^ (length - i); // obfuscated[i] = obfuscated[i] ^ sizeof(obfuscataed) - i
      if ( i < length )
      {
        if ( *data > 1u || (v5 = data, offset != 24) )
        {
          QByteArray::reallocData(a1, (*(data + 1) + 1), *(data + 11) >> 31);
          v5 = *a1;
          offset = *(*a1 + 16LL);
        }
      }
      else
      {
        QByteArray::expand(a1, i);
        v5 = *a1;
        offset = *(*a1 + 16LL);
      }
      ++i;
      *(v5 + v7 + offset) = v8;
      data = *a1;
      length = *(*a1 + 4LL);
    }
    while ( length > i );
  }
  return data;
}
