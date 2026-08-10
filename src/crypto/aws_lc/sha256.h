#include <stddef.h>
#include <stdint.h>

uint8_t *SHA256(const uint8_t *data, size_t len, uint8_t *out);

typedef struct evp_aead_st EVP_AEAD;
typedef struct engine_st ENGINE;

union evp_aead_ctx_st_state {
  uint8_t opaque[564];
  uint64_t alignment;
  void *ptr;
};

typedef struct evp_aead_ctx_st {
  const EVP_AEAD *aead;
  union evp_aead_ctx_st_state state;
  uint8_t state_offset;
  uint8_t tag_len;
} EVP_AEAD_CTX;

const EVP_AEAD *EVP_aead_aes_128_gcm(void);
const EVP_AEAD *EVP_aead_aes_256_gcm(void);
void EVP_AEAD_CTX_zero(EVP_AEAD_CTX *ctx);
int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
                      const uint8_t *key, size_t key_len,
                      size_t tag_len, ENGINE *impl);
void EVP_AEAD_CTX_cleanup(EVP_AEAD_CTX *ctx);
int EVP_AEAD_CTX_seal_scatter(
    const EVP_AEAD_CTX *ctx, uint8_t *out, uint8_t *out_tag,
    size_t *out_tag_len, size_t max_out_tag_len, const uint8_t *nonce,
    size_t nonce_len, const uint8_t *in, size_t in_len, const uint8_t *extra_in,
    size_t extra_in_len, const uint8_t *ad, size_t ad_len);
int EVP_AEAD_CTX_open_gather(
    const EVP_AEAD_CTX *ctx, uint8_t *out, const uint8_t *nonce,
    size_t nonce_len, const uint8_t *in, size_t in_len, const uint8_t *in_tag,
    size_t in_tag_len, const uint8_t *ad, size_t ad_len);
