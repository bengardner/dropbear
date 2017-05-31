/**
 * @file svr-pw_crypt.c
 * crypt() replacement that supports MD5 ($1$SALT), SHA-256 ($5$SALT),
 * and SHA-512 ($6$SALT) passwords. Does not support DES passwords.
 *
 * Included directly into svr-authpasswd.c.
 */
#include "tomcrypt.h"	/* sha256_init(), etc */

typedef hash_state md5_ctx_t;
#define md5_update    md5_process
#define md5_final     md5_done

typedef hash_state sha256_ctx_t;
#define sha256_update sha256_process
#define sha256_final  sha256_done

typedef hash_state sha512_ctx_t;
#define sha512_update sha512_process
#define sha512_final  sha512_done

static inline int min_int(int a, int b)
{
   return (a < b) ? a : b;
}

/* Find the first occurrence of C in S or the final NUL byte.  */
static const char *strchrnul(const char *s, int c_in)
{
   if (s == 0)
   {
      return s;
   }

   while ((*s != 0) && (*s != c_in))
   {
      s++;
   }
   return s;
}

static int i64c(int i)
{
   i &= 0x3f;
   if (i == 0)
      return '.';
   if (i == 1)
      return '/';
   if (i < 12)
      return ('0' - 2 + i);
   if (i < 38)
      return ('A' - 12 + i);
   return ('a' - 38 + i);
}

static char*
to64(char *s, unsigned v, int n)
{
   while (--n >= 0)
   {
      /* *s++ = ascii64[v & 0x3f]; */
      *s++ = i64c(v);
      v >>= 6;
   }
   return s;
}

#define MD5_OUT_BUFSIZE 36

/**
 * Does the crypt() thing for a salt that starts with "$1$".
 *
 * @param result  result buffer
 * @param pw      the password to hash
 * @param salt    "$1$..."
 * @return result (pass-through)
 */
static char *
db_crypt_md5(char result[MD5_OUT_BUFSIZE], const char *pw, const char *salt)
{
   char *p;
   uint8_t final[17]; /* final[16] exists only to aid in looping */
   int sl, pl, i, pw_len;
   hash_state ctx, ctx1;

   /* Get the length of the salt including "$1$" */
   sl = 3;
   while (sl < (3 + 8) && salt[sl] && salt[sl] != '$')
   {
      sl++;
   }

   /* Hash the password first, since that is what is most unknown */
   md5_init(&ctx);
   pw_len = strlen(pw);
   md5_update(&ctx, pw, pw_len);

   /* Then the salt including "$1$" */
   md5_update(&ctx, salt, sl);

   /* Copy salt to result => "$1$26I2bvpt$" */
   memcpy(result, salt, sl);
   result[sl] = '$';

   /* skip "$1$" */
   salt += 3;
   sl -= 3;

   /* Then just as many characters of the MD5(pw, salt, pw) */
   md5_init(&ctx1);
   md5_update(&ctx1, pw, pw_len);
   md5_update(&ctx1, salt, sl);
   md5_update(&ctx1, pw, pw_len);
   md5_final(&ctx1, final);
   for (pl = pw_len; pl > 0; pl -= 16)
   {
      md5_update(&ctx, final, pl > 16 ? 16 : pl);
   }

   /* Then something really weird... */
   memset(final, 0, sizeof(final));
   for (i = pw_len; i; i >>= 1)
   {
      md5_update(&ctx, ((i & 1) ? final : (const uint8_t *) pw), 1);
   }
   md5_final(&ctx, final);

   /* And now, just to make sure things don't run too fast.
    * On a 60 Mhz Pentium this takes 34 msec, so you would
    * need 30 seconds to build a 1000 entry dictionary...
    */
   for (i = 0; i < 1000; i++)
   {
      md5_init(&ctx1);
      if (i & 1)
      {
         md5_update(&ctx1, pw, pw_len);
      }
      else
      {
         md5_update(&ctx1, final, 16);
      }

      if (i % 3)
      {
         md5_update(&ctx1, salt, sl);
      }

      if (i % 7)
      {
         md5_update(&ctx1, pw, pw_len);
      }

      if (i & 1)
      {
         md5_update(&ctx1, final, 16);
      }
      else
      {
         md5_update(&ctx1, pw, pw_len);
      }
      md5_final(&ctx1, final);
   }

   p = result + sl + 4; /* 12 bytes max (sl is up to 8 bytes) */

   /* Add 5*4+2 = 22 bytes of hash, + NUL byte. */
   final[16] = final[5];
   for (i = 0; i < 5; i++)
   {
      unsigned l = (final[i] << 16) | (final[i+6] << 8) | final[i+12];
      p = to64(p, l, 4);
   }
   p = to64(p, final[11], 2);
   *p = '\0';

   /* Don't leave anything around in vm they could use. */
   memset(final, 0, sizeof(final));

   return result;
}

/* Maximum salt string length.  */
#define SHA_SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define SHA_ROUNDS_DEFAULT 5000

static char *
db_crypt_sha(char result[108], const char *key_data, const char *salt_data)
{
   char p_bytes[512];
   char s_bytes[SHA_SALT_LEN_MAX + 1];
   void (*sha_begin)(void *ctx);
   void (*sha_hash)(void *ctx, const void *buffer, size_t len);
   void (*sha_end)(void *ctx, void *resbuf);
   int _32or64;
   char *resptr;

   /* btw, sha256 needs [32] and uint32_t only */
   struct
   {
      unsigned char alt_result[64];
      unsigned char temp_result[64];
      union
      {
         sha256_ctx_t x;
         sha512_ctx_t y;
      } ctx;
      union
      {
         sha256_ctx_t x;
         sha512_ctx_t y;
      } alt_ctx;
   } L __attribute__((__aligned__(__alignof__(uint64_t))));
#define alt_result  (L.alt_result )
#define temp_result (L.temp_result)
#define ctx         (L.ctx        )
#define alt_ctx     (L.alt_ctx    )
   unsigned salt_len;
   unsigned key_len;
   unsigned cnt;
   unsigned rounds;
   char *cp;
   char is_sha512;

   /* Analyze salt, construct already known part of result */
   cnt = strlen(salt_data) + 1 + 43 + 1;
   is_sha512 = salt_data[1];
   if (is_sha512 == '6')
   {
      cnt += 43;
   }
   resptr = result; /* will provide NUL terminator */
   *resptr++ = '$';
   *resptr++ = is_sha512;
   *resptr++ = '$';
   rounds = SHA_ROUNDS_DEFAULT;
   salt_data += 3;
   salt_len = strchrnul(salt_data, '$') - salt_data;
   if (salt_len > SHA_SALT_LEN_MAX)
      salt_len = SHA_SALT_LEN_MAX;
   /* add "salt$" to result */
   memcpy(resptr, salt_data, salt_len);
   resptr += salt_len;
   *resptr++ = '$';
   /* key data doesn't need much processing */
   key_len = min_int(strlen(key_data), sizeof(p_bytes) - 1);

   /* Which flavor of SHAnnn ops to use? */
   sha_begin = (void*)sha256_init;
   sha_hash = (void*)sha256_update;
   sha_end = (void*)sha256_final;
   _32or64 = 32;
   if (is_sha512 == '6')
   {
      sha_begin = (void*)sha512_init;
      sha_hash = (void*)sha512_update;
      sha_end = (void*)sha512_final;
      _32or64 = 64;
   }

   /* Add KEY, SALT.  */
   sha_begin(&ctx);
   sha_hash(&ctx, key_data, key_len);
   sha_hash(&ctx, salt_data, salt_len);

   /* Compute alternate SHA sum with input KEY, SALT, and KEY.
      The final result will be added to the first context.  */
   sha_begin(&alt_ctx);
   sha_hash(&alt_ctx, key_data, key_len);
   sha_hash(&alt_ctx, salt_data, salt_len);
   sha_hash(&alt_ctx, key_data, key_len);
   sha_end(&alt_ctx, alt_result);

   /* Add result of this to the other context.  */
   /* Add for any character in the key one byte of the alternate sum.  */
   for (cnt = key_len; cnt > _32or64; cnt -= _32or64)
   {
      sha_hash(&ctx, alt_result, _32or64);
   }
   sha_hash(&ctx, alt_result, cnt);

   /* Take the binary representation of the length of the key and for every
      1 add the alternate sum, for every 0 the key.  */
   for (cnt = key_len; cnt != 0; cnt >>= 1)
      if ((cnt & 1) != 0)
         sha_hash(&ctx, alt_result, _32or64);
      else
         sha_hash(&ctx, key_data, key_len);

   /* Create intermediate result.  */
   sha_end(&ctx, alt_result);

   /* Start computation of P byte sequence.  */
   /* For every character in the password add the entire password.  */
   sha_begin(&alt_ctx);
   for (cnt = 0; cnt < key_len; ++cnt)
   {
      sha_hash(&alt_ctx, key_data, key_len);
   }
   sha_end(&alt_ctx, temp_result);

   /* NB: past this point, raw key_data is not used anymore */

   /* Create byte sequence P.  */
   cp = p_bytes;
   for (cnt = key_len; cnt >= _32or64; cnt -= _32or64)
   {
      cp = memcpy(cp, temp_result, _32or64);
      cp += _32or64;
   }
   memcpy(cp, temp_result, cnt);

   /* Start computation of S byte sequence.  */
   /* For every character in the password add the entire password.  */
   sha_begin(&alt_ctx);
   for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
      sha_hash(&alt_ctx, salt_data, salt_len);
   sha_end(&alt_ctx, temp_result);

   /* NB: past this point, raw salt_data is not used anymore */

   /* Create byte sequence S.  */
   cp = s_bytes; /* was: ... = alloca(salt_len); */
   for (cnt = salt_len; cnt >= _32or64; cnt -= _32or64)
   {
      cp = memcpy(cp, temp_result, _32or64);
      cp += _32or64;
   }
   memcpy(cp, temp_result, cnt);

   /* Repeatedly run the collected hash value through SHA to burn
      CPU cycles.  */
   for (cnt = 0; cnt < rounds; ++cnt)
   {
      sha_begin(&ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
         sha_hash(&ctx, p_bytes, key_len);
      else
         sha_hash(&ctx, alt_result, _32or64);
      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
         sha_hash(&ctx, s_bytes, salt_len);
      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
         sha_hash(&ctx, p_bytes, key_len);
      /* Add key or last result.  */
      if ((cnt & 1) != 0)
         sha_hash(&ctx, alt_result, _32or64);
      else
         sha_hash(&ctx, p_bytes, key_len);

      sha_end(&ctx, alt_result);
   }

   /* Append encrypted password to result buffer */
#define b64_from_24bit(B2, B1, B0, N) \
   do { \
      unsigned w = ((B2) << 16) | ((B1) << 8) | (B0); \
      resptr = to64(resptr, w, N); \
   } while (0)

   if (is_sha512 == '5')
   {
      unsigned i = 0;
      while (1)
      {
         unsigned j = i + 10;
         unsigned k = i + 20;
         if (j >= 30) j -= 30;
         if (k >= 30) k -= 30;
         b64_from_24bit(alt_result[i], alt_result[j], alt_result[k], 4);
         if (k == 29)
            break;
         i = k + 1;
      }
      b64_from_24bit(0, alt_result[31], alt_result[30], 3);
   }
   else
   {
      unsigned i = 0;
      while (1)
      {
         unsigned j = i + 21;
         unsigned k = i + 42;
         if (j >= 63) j -= 63;
         if (k >= 63) k -= 63;
         b64_from_24bit(alt_result[i], alt_result[j], alt_result[k], 4);
         if (j == 20)
            break;
         i = j + 1;
      }
      b64_from_24bit(0, 0, alt_result[63], 2);
   }
   *resptr = '\0';

   /* Clear the buffer for the intermediate result so that people
      attaching to processes or reading core dumps cannot get any
      information.  */
   memset(&L, 0, sizeof(L)); /* [alt]_ctx and XXX_result buffers */
   memset(p_bytes, 0, sizeof(p_bytes));
   memset(s_bytes, 0, sizeof(s_bytes));

   return result;

#undef b64_from_24bit
#undef alt_result
#undef temp_result
#undef ctx
#undef alt_ctx
}

/**
 * Do the crypt() thing with GNU extensions for MD5, SHA-256, SHA-512.
 * Not re-entrant. "rounds" not supported.
 */
char *DROPBEAR_PW_CRYPT(const char *key, const char *salt)
{
   static char result[112] = "TBD";

   /* match "$1$", "$2$", "$3$" */
   if ((salt[0] == '$') && (salt[2] == '$'))
   {
      if (salt[1] == '1')
      {
         return db_crypt_md5(result, key, salt);
      }
      else if ((salt[1] == '5') || (salt[1] == '6'))
      {
         return db_crypt_sha(result, key, salt);
      }
   }
   return NULL;
}
