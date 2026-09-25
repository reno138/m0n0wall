/*
    $Id$
    
    Copyright (C) 2007 Marcel Wiget <mwiget@mac.com>.
    All rights reserved.
    
    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:
    
    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    
    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

/*

   This program creates and verifies captive portal vouchers. A voucher is a
   short printable code that carries its own Roll Id and Ticket Id, so the
   portal can recover both from the typed string alone -- there is no database
   of codes to look up.

   ------------------------------------------------------------------------
   WHY THIS NO LONGER USES RSA
   ------------------------------------------------------------------------

   Until this rewrite the 64-bit voucher word was RSA-encrypted: print did
   RSA_private_encrypt() with a 64-BIT key and check did RSA_public_decrypt().
   Two things killed that, one of them fatal on this platform:

   1. It cannot be built any more. OpenSSL 3 refuses to generate a modulus
      below 512 bits, so the "voucher -g 64" the webGUI called returned NULL:

        error:02000078:rsa routines:rsa_multiprime_keygen:key size too
        small:../crypto/rsa/rsa_gen.c:282

      RSA_generate_key() is also OSSL_DEPRECATEDIN_0_9_8. The GUI therefore
      stored an empty public key and no voucher could be created or checked.
      Raising the key to the 512-bit minimum is not a fix: RSA_size() becomes
      64 bytes, and 512 / log2(54) = 89, so the printed code would grow from
      ~11 characters to ~89 and stop being something a guest can type.

   2. It was not secure even when it did run. print published c = m^d mod N
      for every ticket while check used e = 65537, so N divides (c^e - m) for
      each handed-out voucher. Roll Id is printed on the sheet, Ticket Id is
      1..count, the checksum is derived and the magic is shared by every
      ticket -- so a guest holding a handful of vouchers knows m for each,
      recovers N as a gcd of (c^e - m) over those pairs, factors a 64-bit
      modulus in well under a second, and can then mint every voucher of
      every roll. A 64-bit modulus cannot hold a public/private asymmetry.

   The asymmetry was never used operationally either: printing and checking
   both run on this firewall (the webGUI streams the CSV, the portal validates
   the typed code), so one secret is sufficient.

   ------------------------------------------------------------------------
   WHAT REPLACES IT
   ------------------------------------------------------------------------

   A keyed 64-bit pseudo-random permutation: a 10-round balanced Feistel
   network over the same 64-bit word, with HMAC-SHA256 truncated to 32 bits as
   the round function, under one 256-bit secret.

   This keeps the shape the rest of the design depends on -- 64 bits in, 64
   bits out -- so the charset rendering, the printed length, the voucher.cfg
   format and the CSV output are all unchanged.

   What it guarantees:

     - A guest cannot forge a code. Because the map is a permutation of the
       whole 64-bit space, every typed string decodes to SOME word, so the
       acceptance test is entirely the redundancy inside the word: the magic
       field must match and the checksum must agree with the roll/ticket it
       decoded to. That is 2^-(magic_bits + checksum_bits), and since
       magic_bits = 64 - roll - ticket - checksum the redundancy is exactly
       64 - roll_bits - ticket_bits no matter how the remainder is split.
       The rule enforced below, roll_bits + ticket_bits <= 32, therefore keeps
       at least 32 bits of redundancy at EVERY legal setting; with the shipped
       defaults (16/10/5) it is 33 + 5 = 38 bits, i.e. one accepted guess in
       2.7e11.

     - A guest cannot derive other codes from one they hold. A PRP's output on
       an unqueried input is independent of its outputs on every queried one,
       so tickets 1..5 of roll 0 say nothing about ticket 6 or about roll 7.
       This is precisely what failed under RSA.

     - A guest cannot recover the secret from codes. That would mean inverting
       HMAC-SHA256 on 256 bits of key from 32-bit truncated outputs.

   Everything used is in the OpenSSL 3 DEFAULT provider (EVP_MAC "HMAC" with
   digest "SHA2-256", RAND_bytes, OPENSSL_cleanse, and the one-shot HMAC() for
   the self-test). Nothing here needs the LEGACY provider, so no Blowfish/DES
   and no OSSL_PROVIDER_load in a minimal image. Link line is unchanged
   (-lcrypto).

   ------------------------------------------------------------------------
   THE WORD, AND THE TWO ARITHMETIC CHANGES FROM THE RSA VERSION
   ------------------------------------------------------------------------

   bit 63                                                          bit 0
   +---------------------+------------+------------+---------------+
   |        magic        |  checksum  |  ticketid  |    rollid     |
   +---------------------+------------+------------+---------------+
     magic_bits            cksum_bits   ticket_bits    roll_bits

   1. magic_bits is now 64 - (roll + ticket + checksum). The old code used
      avail_len*8 - (roll + ticket + checksum + 1); the "+1" existed only to
      keep the plaintext below the RSA modulus. A permutation has no modulus,
      so that bit is reclaimed -- with the defaults magic_bits goes 32 -> 33.

   2. The old MSB-clearing line

        clearcode &= 0xffffffffffffffffLL >> (65 - 8*crypt_len);

      is GONE, and must stay gone. At crypt_len 8 it was a >>1, i.e. "clear
      bit 63", which existed only to avoid RSA's "data too large for modulus".
      With magic_bits = 33 the magic field reaches bit 63, so clearing it on
      the print side while check compares against the unclipped magic from
      voucher.cfg would make EVERY voucher fail its magic test -- and the
      failure would look like a broken Feistel, not like a masking bug. Do not
      reintroduce it "for safety". tests/t_voucher.php prints a roll and feeds
      the codes back through -k specifically to catch this; the KAT below does
      not, because the KAT only exercises the permutation and not the packing.

   ------------------------------------------------------------------------
   USAGE
   ------------------------------------------------------------------------

   The key is a single 256-bit secret, 64 lowercase hex digits in a file:

   $ voucher -g > /var/etc/voucher.key

   The same file is used to print and to check. There is no key pair, so
   nothing unlinks the key after printing (that would break validation for
   every guest -- see services_captiveportal_vouchers.php).

   Next, a config file is needed, containing one line as follows:

   rollbits,ticketbits,checksumbits,magic,charset

   An example file looks like:
   $ cat voucher.cfg 
   16,10,5,1174491274,2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ

   Content: more info can also be found in the m0n0wall GUI.

   rollbits:     Number of Bits used to store the Roll Id. 1..31.
   ticketbits:   Number of Bits used to store the Ticket Id. 1..16.
                 rollbits + ticketbits must not exceed 32 (see above).
   checksumbits: Number of Bits used to store a checksum over Roll Id and
                 Ticket Id. 0..31. Under a PRP this is security-neutral --
                 the magic field absorbs whatever the checksum does not use --
                 it exists so a typo reports "Invalid checksum" rather than a
                 wrong roll.
   magic:        a number stored in and verified in every voucher. Its WIDTH
                 is the anti-forgery margin; its value need not be secret,
                 because knowing it does not help invert the permutation.
   charset:      The generated vouchers use characters out of this character
                 set. Avoid e.g. letters/numbers that can be confused like
                 0 and O. Character set is case sensitive.

   To generate and test vouchers using the example settings above, use:

   $ ./voucher -c voucher.cfg -K voucher.key -p 0 5
   # Voucher Tickets 1..5 for Roll 0
   # Nr of Roll Bits     16
   # Nr of Ticket Bits   10
   # Nr of Checksum Bits 5
   # magic initializer   1174491274 (33 Bits used)
   # Character Set used  2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ
   #
   " G8DEa7DeNaN"
   " NRTj3BraAAW"
   " ztVZcVhJZdP"
   " s38KKwZiiAD"
   " E4uw8YFbyzv3"

   Note the magic width in the header now reads 33 rather than 32. That is
   change (1) above, not a regression.

   To test the vouchers, use:

   $ ./voucher -c voucher.cfg -K voucher.key -k -- G8DEa7DeNaN
   OK 0 1

   $ ./voucher -c voucher.cfg -K voucher.key -k -- NRTj3BraAAW ztVZcVhJZdP
   OK 0 2
   OK 0 3

   Unlike the RSA version this prints one result line per code and keeps
   going after a bad one, so the caller can check a whole request in a single
   fork instead of one fork per code. Exit status is 0 only if every code was
   good.

   The codes above are reproducible: they are what this program prints for the
   published KAT key 000102...1f with the config line shown. An independent
   implementation of the spec in this comment (Python and PHP were both used)
   produces the same bytes, and tests/t_voucher.php asserts the PHP one.

   charset: can contain any 8 bit ASCII character except space, double quote
   and comma (' ', '"' and ','). Comma and quote would break the voucher.cfg
   line; a space would be taken as the code terminator by code_parse() below
   and silently truncate every code at that character.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#ifdef DEBUG
#define HELP "\n\
voucher [-d] [-c cfg_file] -K key_file -k voucher ...\n\
voucher [-d] [-c cfg_file] -K key_file -p roll count\n\
voucher [-d] -g\n\
\n"
#else
#define HELP "\n\
voucher [-c cfg_file] -K key_file -k voucher ...\n\
voucher [-c cfg_file] -K key_file -p roll count\n\
voucher -g\n\
\n"
#endif

// default config file, unless specified via option '-c'. 
// This file must contain one line with:
// rollbits,ticketbits,checksumbits,magic,charset
#define DEFAULT_CFG_FILE "./voucher.cfg"

// how many characters we will allow to 
// generate vouchers. If you change this here
// check use places too. Will trigger assert()
#define MAX_CHARSET_LEN 255 

// buffer to hold one voucher string. 
// 64 is enough to hold vouchers with a charset of "01"
#define MAX_VOUCHER_LEN 64

// Version tag mixed into every MAC. Bumping it changes every code, which is
// the upgrade hook if the construction ever has to move.
#define VOUCHER_FPE_VERSION 0x01

/* VOUCHER_FPE_ROUNDS is part of the wire format: changing it invalidates
 * every printed voucher, silently -- the codes simply stop validating, with
 * no error to point at. It is not a runtime tuning knob.
 *
 * Why 10. On 32-bit halves, 4 rounds give a strong (CCA-secure) PRP by
 * Luby-Rackoff, which is the minimum for our threat model because the portal
 * is a verification oracle a guest can query. But that bound is birthday-
 * limited at q^2/2^32, and the GUI permits ticketbits = 16, i.e. 65535 codes
 * under one key -- q^2/2^32 ~ 1 at the configurable maximum, so 4 is not
 * enough here. 5 rounds (CPA) and 6 rounds (CCA) push security past the
 * birthday bound to ~2^32 queries (Patarin, CRYPTO 2004), so 6 is the real
 * cryptographic floor. 10 is what NIST SP 800-38G FF1 uses for this same job
 * and the margin is cheap: with the HMAC key schedule hoisted out of the loop
 * (EVP_MAC_CTX_dup below) one code costs 10 MACs, a default 1023-ticket roll
 * ~9 ms on a modern x86_64 build host and the 65535-ticket worst case ~0.6 s.
 * A 500 MHz Geode LX is roughly 20-30x slower, so the realistic default is
 * still well under a second there while a maxed 65535-ticket roll could take
 * 10-20 s inside the CSV request. That is accepted rather than traded away:
 * the KAT below pins 10 rounds, and 6 would only buy back 40% of it.
 */
#define VOUCHER_FPE_ROUNDS  10

#define VOUCHER_KEY_LEN     32                        /* 256-bit HMAC key */
#define VOUCHER_KEY_HEXLEN  (VOUCHER_KEY_LEN * 2)

// Error messages returned to caller via stdout
#define MSG_OK      "OK"
#define ERR_TYPO    "TYPO"  // bad code, e.g. too short/long, wrong checksum
#define ERR_CRYPT   "CRYPT" // crypto error. See stderr for detailed msg
#define ERR_VRFY    "VRFY"  // verification error
#define ERR_CFG     "CFG"  // config error

#ifdef DEBUG
int         debug = 0;
#endif

static unsigned char  fpe_key[VOUCHER_KEY_LEN];
static EVP_MAC       *fpe_mac   = NULL;   /* "HMAC", default provider    */
static EVP_MAC_CTX   *fpe_keyed = NULL;   /* key + digest installed once */

static void usage()
{
    fprintf(stderr,HELP);
    exit(1);
}

/*
 * Fetch HMAC-SHA256 once, then install whatever is currently in fpe_key.
 * Idempotent: call it again after changing fpe_key to re-key the context.
 * Keeping one keyed context and duplicating it per MAC skips the HMAC key
 * schedule, which is measurably about half the cost of a 6-byte MAC.
 */
static int fpe_init(void)
{
    OSSL_PARAM p[2];

    if (fpe_mac == NULL) {
        fpe_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (fpe_mac == NULL)
            return -1;
    }
    EVP_MAC_CTX_free(fpe_keyed);          /* free(NULL) is fine */
    fpe_keyed = EVP_MAC_CTX_new(fpe_mac);
    if (fpe_keyed == NULL)
        return -1;
    p[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA2-256", 0);
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(fpe_keyed, fpe_key, VOUCHER_KEY_LEN, p) != 1)
        return -1;
    return 0;
}

/*
 * Round function.  F(i, X) = the first 4 bytes, big-endian, of
 *
 *     HMAC-SHA256( K, 0x01 || i || BE32(X) )
 *
 * F need not be injective or invertible: the Feistel XOR structure below is a
 * bijection for ANY F, which is the whole reason this construction can keep
 * the 64-bit-in/64-bit-out shape with no padding, no modulus and no
 * cycle-walking. The round index i lives inside the MAC'd message, so the ten
 * rounds behave as ten independent round functions under one key (HMAC is a
 * PRF, so distinct message prefixes give independent outputs) -- that is the
 * independence the Luby-Rackoff/Patarin analysis assumes.
 *
 * Do NOT also derive per-round subkeys K_i = HMAC(K, "round"||i). It buys
 * nothing and it silently invalidates the KAT, so a later reader cannot tell
 * a build bug from a spec drift.
 */
static int fpe_F(unsigned char round, uint32_t x, uint32_t *out)
{
    unsigned char  in[6];
    unsigned char  mac[EVP_MAX_MD_SIZE];
    size_t         maclen = 0;
    EVP_MAC_CTX   *ctx;

    in[0] = VOUCHER_FPE_VERSION;
    in[1] = round;
    in[2] = (unsigned char)(x >> 24);
    in[3] = (unsigned char)(x >> 16);
    in[4] = (unsigned char)(x >>  8);
    in[5] = (unsigned char)(x      );

    ctx = EVP_MAC_CTX_dup(fpe_keyed);
    if (ctx == NULL)
        return -1;
    if (EVP_MAC_update(ctx, in, sizeof(in)) != 1 ||
        EVP_MAC_final(ctx, mac, &maclen, sizeof(mac)) != 1 || maclen < 4) {
        EVP_MAC_CTX_free(ctx);
        return -1;
    }
    EVP_MAC_CTX_free(ctx);

    *out = ((uint32_t)mac[0] << 24) | ((uint32_t)mac[1] << 16) |
           ((uint32_t)mac[2] <<  8) |  (uint32_t)mac[3];
    return 0;
}

/* ---- the permutation: balanced Feistel on two 32-bit halves ------------ */
static int fpe_encrypt(uint64_t pt, uint64_t *ct)
{
    uint32_t l = (uint32_t)(pt >> 32);
    uint32_t r = (uint32_t)(pt & 0xffffffffULL);
    uint32_t f, t;
    int i;

    for (i = 1; i <= VOUCHER_FPE_ROUNDS; i++) {
        if (fpe_F((unsigned char)i, r, &f) != 0)
            return -1;
        t = l ^ f;
        l = r;
        r = t;
    }
    *ct = ((uint64_t)l << 32) | (uint64_t)r;
    return 0;
}

/*
 * Decrypt runs the identical loop backwards with the halves swapped. Round i
 * maps (L,R) -> (R, L^F(i,R)); given (L',R') the inputs come back as R = L'
 * and L = R' ^ F(i,L'), and F is applied to a value the decryptor already
 * has -- so every round inverts unconditionally and decode never fails.
 */
static int fpe_decrypt(uint64_t ct, uint64_t *pt)
{
    uint32_t l = (uint32_t)(ct >> 32);
    uint32_t r = (uint32_t)(ct & 0xffffffffULL);
    uint32_t f, t;
    int i;

    for (i = VOUCHER_FPE_ROUNDS; i >= 1; i--) {
        if (fpe_F((unsigned char)i, l, &f) != 0)
            return -1;
        t = r ^ f;
        r = l;
        l = t;
    }
    *pt = ((uint64_t)l << 32) | (uint64_t)r;
    return 0;
}

/* ---- key file: exactly 64 hex digits, optional trailing whitespace ----- */
static int hexnib(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Hex rather than base64 on purpose. EVP_DecodeBlock() returns the PADDED
 * length (a multiple of 3: 33 for a 44-character key, 66 for an 88-character
 * line) and does not bound its output by the caller's buffer, so every
 * base64 key reader has to get two separate length checks right before it can
 * refuse a malformed key. 64 hex digits need a 12-line nibble loop, one exact
 * length test and no padding semantics at all.
 */
static int fpe_load_key(const char *path)
{
    char   buf[VOUCHER_KEY_HEXLEN + 4];
    FILE  *f;
    size_t n, i;

    memset(buf, 0, sizeof(buf));
    f = fopen(path, "r");
    if (f == NULL)
        return -1;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' ||
                     buf[n-1] == ' '  || buf[n-1] == '\t'))
        buf[--n] = '\0';
    if (n != VOUCHER_KEY_HEXLEN)          /* rejects short AND over-long */
        return -1;

    for (i = 0; i < VOUCHER_KEY_LEN; i++) {
        int hi = hexnib((unsigned char)buf[2*i]);
        int lo = hexnib((unsigned char)buf[2*i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        fpe_key[i] = (unsigned char)((hi << 4) | lo);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    return 0;
}

/*
 * Self-test, run on every invocation before any real work.
 *
 * It proves three things: that libcrypto gives us HMAC-SHA256 at all, that
 * the permutation inverts, and that THIS build reproduces the published KAT.
 * The last leg matters because a libcrypto or compiler change that altered
 * the round function would otherwise silently orphan an already-printed roll:
 * printing would keep working and only guests would fail. The final check
 * cross-references the fast EVP_MAC_CTX_dup path against the one-shot HMAC(),
 * a second independent route to the same bytes, so the optimisation cannot
 * drift away from the spec undetected.
 *
 * It does NOT cover the packing of roll/ticket/checksum/magic into the word.
 * That is what the end-to-end case in tests/t_voucher.php is for.
 */
static int fpe_selftest(void)
{
    static const unsigned char kat_key[VOUCHER_KEY_LEN] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
    /* 10 rounds, version tag 0x01, key above. Reproduced from the prose spec
     * in the header comment by independent Python and PHP implementations. */
    static const uint64_t kat_pt[4] = {
        0x0000000000000000ULL, 0x0000000000000001ULL,
        0x0123456789abcdefULL, 0xffffffffffffffffULL };
    static const uint64_t kat_ct[4] = {
        0x057a9ff680d00febULL, 0x9a4d227a727a0296ULL,
        0xaeffa80658fe0280ULL, 0x97250f5ad1c932daULL };

    unsigned char saved[VOUCHER_KEY_LEN];
    unsigned char m[EVP_MAX_MD_SIZE], in[6];
    unsigned int  ml = 0;
    uint64_t      ct, back;
    uint32_t      ref, got;
    int           i, rc = 0;

    memcpy(saved,   fpe_key, VOUCHER_KEY_LEN);
    memcpy(fpe_key, kat_key, VOUCHER_KEY_LEN);
    if (fpe_init() != 0)
        return -1;

    for (i = 0; i < 4; i++) {
        if (fpe_encrypt(kat_pt[i], &ct) != 0 || ct   != kat_ct[i]) { rc = -1; break; }
        if (fpe_decrypt(ct, &back)      != 0 || back != kat_pt[i]) { rc = -1; break; }
    }

    in[0] = VOUCHER_FPE_VERSION; in[1] = 7;
    in[2] = 0xde; in[3] = 0xad; in[4] = 0xbe; in[5] = 0xef;
    if (HMAC(EVP_sha256(), kat_key, VOUCHER_KEY_LEN, in, sizeof(in), m, &ml) == NULL
        || ml < 4) {
        rc = -1;
    } else {
        ref = ((uint32_t)m[0]<<24)|((uint32_t)m[1]<<16)|((uint32_t)m[2]<<8)|m[3];
        if (fpe_F(7, 0xdeadbeefUL, &got) != 0 || got != ref)
            rc = -1;
    }

    memcpy(fpe_key, saved, VOUCHER_KEY_LEN);
    OPENSSL_cleanse(saved, sizeof(saved));
    if (fpe_init() != 0)
        return -1;
    return rc;
}

/* ---- -g : emit a fresh secret as 64 hex digits on stdout --------------- */
static int fpe_genkey(void)
{
    unsigned char k[VOUCHER_KEY_LEN];
    int i;

    if (RAND_bytes(k, sizeof(k)) != 1) {
        fprintf(stderr, "voucher: RAND_bytes failed\n");
        return -1;
    }
    for (i = 0; i < VOUCHER_KEY_LEN; i++)
        printf("%02x", k[i]);
    printf("\n");
    OPENSSL_cleanse(k, sizeof(k));
    return 0;
}

/*
 * Render a 64-bit value in base strlen(charset), least significant digit
 * first -- byte for byte the layout m0n0wall has always printed.
 *
 * One behavioural fix over the old inline loop (which was
 * "while (cryptcode && --num)"): that emitted an EMPTY string when the
 * ciphertext happened to be 0, which is a legal ciphertext now that the map
 * is a permutation over the full 64-bit space. Emit charset[0] instead.
 */
static int code_render(uint64_t v, const char *charset, char *out, size_t outsz)
{
    uint64_t base = (uint64_t)strlen(charset);
    char     tmp[MAX_VOUCHER_LEN + 1];
    size_t   n = 0;

    if (v == 0)
        tmp[n++] = charset[0];
    while (v != 0) {
        if (n >= sizeof(tmp))
            return -1;
        tmp[n++] = charset[v % base];
        v /= base;
    }
    if (n + 1 > outsz)
        return -1;
    memcpy(out, tmp, n);
    out[n] = '\0';
    return (int)n;
}

/*
 * Inverse of code_render(). Scans right to left and stops at a space, which
 * is inherited behaviour: the CSV prints each code as " %s", so a pasted
 * line still parses.
 *
 * Two things the old inline loop got wrong:
 *
 *   - No overflow check. It did "cryptcode *= base; cryptcode += digit" with
 *     no bound, so an over-long typed string wrapped mod 2^64 and many
 *     distinct strings aliased onto one value -- a padded variant of somebody
 *     else's code could validate AS that code. Refuse instead.
 *   - A string that was only whitespace, or had a trailing space, consumed
 *     zero digits and "succeeded" with v = 0, which then decrypts to some
 *     word and leans on the 2^-38 magic test instead of being rejected
 *     outright. Require at least one digit.
 */
static int code_parse(const char *s, const char *charset, uint64_t *out)
{
    uint64_t    base = (uint64_t)strlen(charset);
    uint64_t    v = 0;
    size_t      digits = 0;
    const char *p = s + strlen(s);

    if (strlen(s) > MAX_VOUCHER_LEN)
        return -1;
    while (p > s) {
        const char *q;
        uint64_t    d;
        p--;
        if (' ' == *p)
            break;
        q = strchr(charset, (unsigned char)*p);
        if (q == NULL)
            return -1;                        /* character not in charset */
        d = (uint64_t)(q - charset);
        if (v > (UINT64_MAX - d) / base)
            return -1;                        /* too long to be one of ours */
        v = v * base + d;
        digits++;
    }
    if (digits == 0)
        return -1;
    *out = v;
    return 0;
}

/*  ================================================================ */
int main(int argc, char *argv[]) {

    enum        {UNDEFINED, PRINT, CHECK, GENKEY} action = UNDEFINED;

    char        *keyFile = NULL;
    char        *cfgFile = DEFAULT_CFG_FILE;
    FILE		*fcfg;

    char        codebuf[MAX_VOUCHER_LEN+1];

    uint64_t    clearcode,cryptcode,magic;
    uint32_t    rollid = 0, ticketid;
    uint32_t    checksum;
    uint32_t    ticketcount = 0;

    int         roll_bits, ticket_bits, checksum_bits, magic_bits;

    char        charset[MAX_CHARSET_LEN+1];
    int         ch;
    int         failed = 0;

    /* fscanf/printf of a uint64_t with %llu is a type mismatch wherever
       uint64_t is unsigned long (every LP64 target). Use the wide type at the
       stdio boundary and convert. */
    unsigned long long magic_in = 0;

    while ((ch = getopt(argc, argv, "dpkc:K:g")) != -1)
    {
        switch(ch)
        {
#ifdef DEBUG
            case 'd':     // increase debug level
                debug++; 
                break;
#endif
            case 'k':     // check voucher(s)
                action = CHECK;
                break;

            case 'p':     // print voucher(s)
                action = PRINT;
                break;

            case 'K':     // the single voucher secret (64 hex digits)
                keyFile = optarg;
                break;

            case 'c':     // config file
                cfgFile = optarg;
                break;
            
            case 'g':     // generate a new voucher secret
                action = GENKEY;
                break;

            case '?':
            default:
                usage();

        }
    }
    argc -= optind;
    argv += optind;

    if (PRINT == action && 2 == argc && keyFile)
    {
        // print vouchers: we need exactly two arguments:
        // roll# and # of vouchers to print
        rollid = (uint32_t)strtoul(argv[0], NULL, 10);
        ticketcount = (uint32_t)strtoul(argv[1], NULL, 10);
#ifdef DEBUG
        if (debug)
            fprintf(stderr, "PRINT roll=%u count=%u\n", rollid, ticketcount);
#endif
    }
    else if (CHECK == action && argc && keyFile)
    {
        // check voucher: one or more voucher strings must be present
    }
    else if (GENKEY == action)
    {
        // generate a secret. No key file and no config needed.
    }
    else
        usage();

    /* Crypto self-test before anything else, including -g: if this platform's
     * HMAC-SHA256 does not match the KAT we must refuse to print codes we
     * would not later be able to validate. */
    if (fpe_init() != 0)
    {
        printf(ERR_CRYPT " cannot initialise HMAC-SHA256 from the default provider\n");
        exit(1);
    }
    if (fpe_selftest() != 0)
    {
        printf(ERR_CRYPT " voucher crypto self-test FAILED. Refusing to run.\n");
        exit(1);
    }

    if (GENKEY == action)
    {
        if (fpe_genkey() != 0)
            exit(1);
        exit(0);
    }

    /* load the secret ------------------------------------------------ */
    if (fpe_load_key(keyFile) != 0)
    {
        printf(ERR_CRYPT " cannot read voucher secret from '%s'"
               " (expected %d hex digits)\n", keyFile, VOUCHER_KEY_HEXLEN);
        exit(1);
    }
    if (fpe_init() != 0)          /* install the real key */
    {
        printf(ERR_CRYPT " cannot install voucher secret\n");
        exit(1);
    }

    /* load cfg file -------------------------------------------- */

    fcfg = fopen(cfgFile, "r");
    if (fcfg == NULL)
    {
        fprintf(stderr, "can't read config file '%s'\n", cfgFile);
        exit(1);
    }
    assert(255 == MAX_CHARSET_LEN); // make sure we're safe with fscanf below
    if (5 != fscanf(fcfg, "%d,%d,%d,%llu,%255s", 
                &roll_bits, &ticket_bits, &checksum_bits, &magic_in, charset))
    {
        printf(ERR_CFG " bad content in cfg file %s\n", cfgFile);
        exit(1);
    }
    fclose(fcfg);
    magic = (uint64_t)magic_in;

    if (strlen(charset) < 2)
    {
        printf(ERR_CFG " charset too short '%s'\n", charset);
        exit(1);
    }

    /* Same ranges the Vouchers page enforces. Checked here as well because
       voucher.cfg is hand-editable and is also rewritten from a restored
       config.xml that never passed through the validation page. */
    if (roll_bits < 1 || roll_bits > 31 ||
        ticket_bits < 1 || ticket_bits > 16 ||
        checksum_bits < 0 || checksum_bits > 31)
    {
        printf(ERR_CFG " roll bits must be 1..31, ticket bits 1..16,"
               " checksum bits 0..31\n");
        exit(1);
    }

    /* The anti-forgery floor, and the reason it is a hard refusal rather than
       a warning: redundancy = magic_bits + checksum_bits = 64 - roll_bits -
       ticket_bits, so this rule alone guarantees at least 32 bits of it at
       every legal setting. The old GUI permitted 31 + 16 + 16, which under a
       permutation would leave 1 magic bit and 17 bits of total redundancy --
       about 131000 expected guesses, a weekend at 10 tries/second. */
    if (roll_bits + ticket_bits > 32)
    {
        printf(ERR_CFG " roll bits + ticket bits must not exceed 32"
               " (got %d + %d)\n", roll_bits, ticket_bits);
        exit(1);
    }

    // The conversion base -- the number of characters the printed code may be
    // built from -- is strlen(charset). Think dec/hex/oct and you'll get it.
    // code_render()/code_parse() take it from the charset directly.

#ifdef DEBUG
    if (debug)
        fprintf(stderr, "roll_bits=%d ticket_bits=%d checksum_bits=%d base=%d charset=%s\n",
                roll_bits, ticket_bits, checksum_bits, (int)strlen(charset), charset);
#endif

    /* Whatever roll, ticket and checksum leave of the 64 bits holds the magic.
       No "+1" and no MSB reserve: a permutation has no modulus to stay below.
       See the header comment -- this is the change that takes magic_bits from
       32 to 33 at the defaults, and it is why the old MSB-clearing line had
       to go. */
    magic_bits = 64 - (roll_bits + ticket_bits + checksum_bits);
    if (magic_bits > 0) {
        magic &= (magic_bits >= 64) ? ~(uint64_t)0
                                    : ((1ULL << magic_bits) - 1);
    } else {
        magic = 0;  // sorry, all bits are used. No magic to verify
        magic_bits = 0;
    }

    if (CHECK == action) // ==================================================
    {
        /* One result line per code, and we keep going after a bad one, so a
           whole request can be checked in a single fork. The old code exited
           on the first failure, which is why voucher_auth() forked per code. */
        while (argc)
        {
            /* Convert alphanumeric code in a number */
#ifdef DEBUG
            if (debug)
                fprintf(stderr, "Test voucher <%s>\n", argv[0]);
#endif

            if (code_parse(argv[0], charset, &cryptcode) != 0)
            {
                printf(ERR_TYPO " Invalid code <%s>\n", argv[0]);
                failed = 1;
                argc--; argv++;
                continue;
            }

            if (fpe_decrypt(cryptcode, &clearcode) != 0)
            {
                printf(ERR_CRYPT " decrypt failed <%s>\n", argv[0]);
                failed = 1;
                argc--; argv++;
                continue;
            }

            /* extract info's out of decrypted code. 1ULL, not 1: the old code
               shifted a signed int, which is undefined at roll_bits = 31 --
               a value the GUI accepts. */
            rollid   = (uint32_t)( clearcode                            & ((1ULL << roll_bits) - 1));
            ticketid = (uint32_t)((clearcode >> roll_bits)              & ((1ULL << ticket_bits) - 1));
            checksum = (uint32_t)((clearcode >> (roll_bits+ticket_bits)) & ((1ULL << checksum_bits) - 1));

            /* verify magic. Under a permutation every typed string decodes to
               SOME word, so this test plus the checksum below IS the whole
               acceptance criterion -- see the header comment. */
            if (magic != (clearcode >> (roll_bits+ticket_bits+checksum_bits))) {
                printf(ERR_TYPO " Invalid magic <%s>\n", argv[0]);
#ifdef DEBUG
                if (debug) {
                    fprintf(stderr,"magic should be %llu but is %llu magic_bits=%d\n",
                            (unsigned long long)magic,
                            (unsigned long long)(clearcode >> (roll_bits+ticket_bits+checksum_bits)),
                            magic_bits);
                }
#endif
                failed = 1;
                argc--; argv++;
                continue;
            }
#ifdef DEBUG
            if (debug)
            {
                fprintf(stderr,"roll=%u ticket=%u checksum=%u magic=%llu voucher=%s clearcode=%llu\n",
                        rollid, ticketid, checksum, (unsigned long long)magic,
                        argv[0], (unsigned long long)clearcode);
            }
#endif

            /* simple checksum test to see if user input was valid */
            if (checksum_bits > 0 &&
                ((uint64_t)ticketid + rollid) % (1ULL << checksum_bits) != checksum)
            {
                printf(ERR_TYPO " Invalid checksum <%s>\n", argv[0]);
                failed = 1;
            }
            else
                printf(MSG_OK " %u %u\n", rollid, ticketid);

            argc--;
            argv++;
        }
    }
    else if (PRINT == action) // ============================================
    {
        if ( (ticketcount >= 1ULL<<ticket_bits) || (ticketcount < 1) )
        {
            printf("Error: Number of Ticket must be 1..%llu\n", 
                    (unsigned long long)((1ULL<<ticket_bits) -1));
            exit(1);
        }
        if (rollid >= 1ULL<<roll_bits)
        {
            printf("Error: Roll# must be 0..%llu\n",
                    (unsigned long long)((1ULL<<roll_bits) -1));
            exit(1);
        }

        /* ------------------------------------------------------*/
        printf("# Voucher Tickets 1..%u for Roll %u\n",ticketcount,rollid);
        printf("# Nr of Roll Bits     %d\n", roll_bits);
        printf("# Nr of Ticket Bits   %d\n", ticket_bits);
        printf("# Nr of Checksum Bits %d\n", checksum_bits);
        printf("# magic initializer   %llu (%d Bits used)\n",
                (unsigned long long)magic, magic_bits);
        printf("# Character Set used  %s\n", charset);
        printf("#\n");

        /* create individual tickets. Start with ticket 1 because the roll
         * bitmask and the "$nr <= count" test in voucher.inc are 1-based.
         * (The old reason -- that roll 0 ticket 0 would encrypt to 0 under
         * RSA -- no longer applies: a Feistel maps 0 to a random-looking
         * value and code_render() prints it correctly.)
         */

        for (ticketid=1; ticketid <= ticketcount; ticketid++) {

            clearcode = magic;
            checksum  = checksum_bits > 0
                        ? (uint32_t)(((uint64_t)ticketid + rollid) % (1ULL << checksum_bits))
                        : 0;
            clearcode = (clearcode << checksum_bits) + checksum;
            clearcode = (clearcode << ticket_bits)   + ticketid;
            clearcode = (clearcode << roll_bits)     + rollid;
            /* NO MSB masking here. See the header comment: the old
               "clearcode &= 0xffff..LL >> (65 - 8*crypt_len)" cleared bit 63,
               which is now a magic bit, so keeping it would make every
               printed voucher fail its own magic check. */

            /* encrypt code */
            if (fpe_encrypt(clearcode, &cryptcode) != 0)
            {
                printf("# FATAL encryption error! ticket=%u\n", ticketid);
                exit (4);
            }

            /* pretty print using charset given above */
            if (code_render(cryptcode, charset, codebuf, sizeof(codebuf)) < 0)
            {
                printf(ERR_CFG " voucher gets too long. Charset too small?\n");
                exit(1);
            }
            // Finally: print the newly created voucher !!
            printf("\" %s\"\n",codebuf);

#ifdef DEBUG
            if (debug)
            {
                fprintf(stderr,"roll=%u ticket=%u checksum=%u voucher=%s clearcode=%llu\n",
                        rollid, ticketid, checksum, codebuf,
                        (unsigned long long)clearcode);
            }
#endif
        }
    }

    EVP_MAC_CTX_free(fpe_keyed);
    EVP_MAC_free(fpe_mac);
    OPENSSL_cleanse(fpe_key, sizeof(fpe_key));

    exit (failed ? 1 : 0);
}
