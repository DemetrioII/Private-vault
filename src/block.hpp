#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <sodium.h>

constexpr std::size_t block_size = 4096;
constexpr std::size_t block_nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t block_payload_size = block_size - 3 * sizeof(std::size_t) - block_nonce_size;

constexpr std::size_t block_tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;

struct Block {
  std::size_t physical_index; // index of block in general Vault's store
  std::size_t logical_index;  // index of block in sequence of blocks for custom file
  std::size_t file_id;
  std::array<unsigned char, block_nonce_size> nonce;
  std::array<unsigned char, block_payload_size> payload;

  ~Block() { payload.fill(0); }
};

static_assert(sizeof(Block) == block_size);
