# `simpfuscator`

A shitty obfuscator that uses encryption (if u can even call it that) that I built for my Information Security project. \
intended to have 2 modes of working :  
1. **`Ghost child`** : The "obfuscated" binary produced encrypts and stores input binary bytes, then simply just creates a child process which executes input binary and deletes after execution.
2. **`Shellcode`** : The obfuscated binary simply encrypts and stores shellcode of target functions. Then at runtime, decrypts and puts the shellcode on stack to execute. 

current version only got the first mode working, pushing second soon

## Usage
```
python3 obfuscator.py <input_binary_path> <output_binary_absolute_path> <encryption_option>
```
> [!NOTE]
> `encryption_option` - can be 1,2,3 (xor, rsa, aes) specifying which encryption algo is used to encrypt bytecode / shellcode in the output binary.

***

## Example
<img width="1332" height="186" alt="image" src="https://github.com/user-attachments/assets/7ba8c634-53d5-4ee6-8617-c12b68ff29b1" />
<img width="720" height="96" alt="image" src="https://github.com/user-attachments/assets/14349bf3-a249-4321-9a0e-e659e29bd1db" />

### before obfuscation :
<img width="584" height="485" alt="image" src="https://github.com/user-attachments/assets/ae1d21d9-53a1-4dcd-b7e9-b0b59b32877d" />

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __printf_chk(1LL, "ye duniya, ye duniya pittal di", envp);
  __printf_chk(1LL, "%d\n", 10LL);
  return 0;
}
```

*** 
### after obfuscation :
<img width="406" height="517" alt="image" src="https://github.com/user-attachments/assets/2d430413-1d2a-4d61-9813-f30ff1b88740" />

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned __int64 v3; // rdx
  __m128i v4; // xmm1
  const __m128i *v5; // rax
  const __m128i *v6; // rcx
  __m128i v7; // xmm0
  unsigned __int64 v8; // rax
  unsigned __int64 v9; // rcx
  unsigned __int64 v10; // rcx
  unsigned __int64 v11; // rax
  int v12; // ebp
  __int64 v13; // rdx
  unsigned __int64 i; // rbx
  ssize_t v15; // rax
  __int64 result; // rax
  int v17; // eax
  int v18; // er8
  int v19; // er8
  int stat_loc; // [rsp+1Ch] [rbp-5Ch] BYREF
  char *argv[2]; // [rsp+20h] [rbp-58h] BYREF
  char templatea[16]; // [rsp+30h] [rbp-48h] BYREF
  __int16 v23; // [rsp+40h] [rbp-38h]
  unsigned __int64 v24; // [rsp+48h] [rbp-30h]

  v3 = qword_8EA0;
  v24 = __readfsqword(0x28u);
  if ( qword_8EA0 )
  {
    if ( (unsigned __int64)(qword_8EA0 - 1) <= 0xE )
    {
      v8 = 0LL;
    }
    else
    {
      v4 = _mm_load_si128((const __m128i *)&xmmword_3260);
      v5 = (const __m128i *)byte_5020;
      v6 = (const __m128i *)&byte_5020[qword_8EA0 & 0xFFFFFFFFFFFFFFF0LL];
      do
      {
        v7 = _mm_load_si128(v5++);
        v5[-1] = _mm_xor_si128(v7, v4);
      }
      while ( v5 != v6 );
      v8 = v3 & 0xFFFFFFFFFFFFFFF0LL;
      if ( (v3 & 0xF) == 0 )
        goto LABEL_15;
    }
    v9 = v3 - v8;
    if ( v3 - v8 - 1 <= 6
      || (*(_QWORD *)&byte_5020[v8] = _mm_xor_si128(
                                        _mm_loadl_epi64((const __m128i *)&byte_5020[v8]),
                                        _mm_loadl_epi64((const __m128i *)&xmmword_3260)).m128i_u64[0],
          v8 += v9 & 0xFFFFFFFFFFFFFFF8LL,
          v9 != (v9 & 0xFFFFFFFFFFFFFFF8LL)) )
    {
      byte_5020[v8] ^= 0x82u;
      if ( v3 > v8 + 1 )
      {
        byte_5020[v8 + 1] ^= 0x82u;
        if ( v3 > v8 + 2 )
        {
          byte_5020[v8 + 2] ^= 0x82u;
          if ( v3 > v8 + 3 )
          {
            byte_5020[v8 + 3] ^= 0x82u;
            if ( v3 > v8 + 4 )
            {
              byte_5020[v8 + 4] ^= 0x82u;
              v10 = v8 + 5;
              if ( v3 > v8 + 5 )
              {
                v11 = v8 + 6;
                byte_5020[v10] ^= 0x82u;
                if ( v3 > v11 )
                  byte_5020[v11] ^= 0x82u;
              }
            }
          }
        }
      }
    }
  }
LABEL_15:
  v23 = 88;
  *(__m128i *)templatea = _mm_load_si128((const __m128i *)&xmmword_3270);
  v12 = mkstemp(templatea);
  if ( v12 < 0 )
  {
    perror("mkstemp");
    return 4LL;
  }
  v13 = qword_8EA0;
  for ( i = 0LL; qword_8EA0 > i; v13 = qword_8EA0 )
  {
    v15 = write(v12, &byte_5020[i], v13 - i);
    if ( v15 >= 0 )
    {
      i += v15;
    }
    else if ( *__errno_location() != 4 )
    {
      perror("write");
      close(v12);
      unlink(templatea);
      return 5LL;
    }
  }
  if ( fsync(v12) == -1 )
    perror("fsync");
  if ( close(v12) == -1 )
  {
    perror("close");
    unlink(templatea);
    result = 6LL;
  }
  else if ( chmod(templatea, 0x1C0u) == -1 )
  {
    perror("chmod");
    unlink(templatea);
    result = 7LL;
  }
  else
  {
    v17 = fork();
    if ( v17 < 0 )
    {
      perror("fork");
      unlink(templatea);
      result = 8LL;
    }
    else
    {
      if ( !v17 )
      {
        argv[0] = templatea;
        argv[1] = 0LL;
        execv(templatea, argv);
        perror("execv");
        _exit(127);
      }
      stat_loc = 0;
      if ( waitpid(v17, &stat_loc, 0) == -1 )
      {
        perror("waitpid");
        v19 = unlink(templatea);
        result = 9LL;
        if ( v19 == -1 )
        {
          perror("unlink");
          result = 9LL;
        }
      }
      else
      {
        v18 = unlink(templatea);
        result = 0LL;
        if ( v18 == -1 )
        {
          perror("unlink");
          result = 10LL;
        }
      }
    }
  }
  return result;
}
```

i suppose this thing is practically like an easy shitty reverse engineering challenge but oh whatever, I tried
