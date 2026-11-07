#include <securebuffer.hpp>
#include <vault.hpp>

#include <cstddef>
#include <filesystem>
#include <iostream>
#include <limits>
#include <optional>
#include <string_view>
#include <unistd.h>

namespace {

constexpr std::size_t password_capacity = 256;
constexpr std::size_t default_capacity = 64 * 1024 * 1024;

enum class Mode { None, Create, AddFile, RemoveFile };

struct Options {
  Mode mode = Mode::None;
  std::filesystem::path vault_path = ".libre-vault";
  std::filesystem::path file_path;
  std::size_t file_id = 0;
  std::size_t capacity = default_capacity;
  bool remove_origin = false;
};

void print_usage(std::ostream &out) {
  out << "Usage:\n"
      << "  libre-vault --create <vault> [--capacity <bytes>]\n"
      << "  libre-vault --add-file <file> [--vault <vault>] [--remove-origin]\n"
      << "  libre-vault --remove-file <file_id> [--vault <vault>]\n"
      << "\n"
      << "Options:\n"
      << "  --create <vault>    Create a new empty vault.\n"
      << "  --add-file <file>   Add a file to the vault.\n"
      << "  --remove-file <id>  Remove a file by id.\n"
      << "  --vault <path>      Vault path (default: .libre-vault).\n"
      << "  --capacity <bytes>  Vault capacity for --create (default: "
      << default_capacity << ").\n"
      << "  --remove-origin     Delete the source file after a successful add.\n"
      << "  -h, --help          Show this help.\n";
}

std::optional<std::size_t> parse_size(std::string_view text) {
  if (text.empty()) {
    return std::nullopt;
  }

  std::size_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }

    const auto digit = static_cast<std::size_t>(c - '0');
    if (value > (std::numeric_limits<std::size_t>::max() - digit) / 10) {
      return std::nullopt;
    }
    value = value * 10 + digit;
  }

  return value;
}

bool set_mode(Options &options, Mode mode) {
  if (options.mode != Mode::None && options.mode != mode) {
    return false;
  }
  options.mode = mode;
  return true;
}

bool parse_args(int argc, char **argv, Options &options) {
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg{argv[i]};

    if (arg == "--create") {
      if (++i >= argc || !set_mode(options, Mode::Create)) {
        return false;
      }
      options.vault_path = argv[i];
    } else if (arg == "--add-file") {
      if (++i >= argc || !set_mode(options, Mode::AddFile)) {
        return false;
      }
      options.file_path = argv[i];
    } else if (arg == "--remove-file") {
      if (++i >= argc || !set_mode(options, Mode::RemoveFile)) {
        return false;
      }
      const auto id = parse_size(argv[i]);
      if (!id.has_value()) {
        return false;
      }
      options.file_id = *id;
    } else if (arg == "--vault") {
      if (++i >= argc) {
        return false;
      }
      options.vault_path = argv[i];
    } else if (arg == "--capacity") {
      if (++i >= argc) {
        return false;
      }
      const auto capacity = parse_size(argv[i]);
      if (!capacity.has_value()) {
        return false;
      }
      options.capacity = *capacity;
    } else if (arg == "--remove-origin") {
      options.remove_origin = true;
    } else {
      return false;
    }
  }

  return options.mode != Mode::None;
}

const char *describe(VaultError error) {
  switch (error) {
  case VaultError::NoEnoughMemory:
    return "not enough memory in the vault";
  case VaultError::FileOpenError:
    return "cannot open file";
  case VaultError::FileReadError:
    return "cannot read file";
  case VaultError::FileWriteError:
    return "cannot write vault";
  case VaultError::BlockDeviceWriteError:
    return "cannot write block";
  case VaultError::CryptoError:
    return "cryptographic operation failed";
  case VaultError::KDF_Error:
    return "key derivation failed";
  case VaultError::FileNotFound:
    return "file not found in the vault";
  case VaultError::BlockDeviceDeallocError:
    return "cannot free blocks";
  case VaultError::InvalidFormat:
    return "invalid vault format";
  case VaultError::WrongPassword:
    return "wrong password or corrupted vault";
  }

  return "unknown error";
}

int fail(const char *message) {
  std::cerr << "error: " << message << '\n';
  return 1;
}

int fail(VaultError error) { return fail(describe(error)); }

} // namespace

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg{argv[i]};
    if (arg == "-h" || arg == "--help") {
      print_usage(std::cout);
      return 0;
    }
  }

  Options options;
  if (!parse_args(argc, argv, options)) {
    print_usage(std::cerr);
    return 2;
  }

  SecureBuffer password(password_capacity);
  if (::isatty(STDIN_FILENO) != 0) {
    std::cout << "Password: " << std::flush;
  }

  if (!(std::cin >> password)) {
    return fail("cannot read password");
  }

  if (options.mode == Mode::Create) {
    auto vault = Vault::create(options.vault_path, options.capacity, password);
    if (!vault) {
      return fail(vault.error());
    }

    std::cout << "Vault created: " << options.vault_path.string() << '\n';
    return 0;
  }

  auto vault = Vault::open(options.vault_path, password);
  if (!vault) {
    return fail(vault.error());
  }

  if (options.mode == Mode::AddFile) {
    auto added = vault->add_file(options.file_path);
    if (!added) {
      return fail(added.error());
    }

    auto saved = vault->save(options.vault_path);
    if (!saved) {
      return fail(saved.error());
    }

    std::cout << "File added, id=" << *added << '\n';

    if (options.remove_origin) {
      std::error_code ec;
      std::filesystem::remove(options.file_path, ec);
      if (ec) {
        std::cerr << "error: cannot remove origin: " << ec.message() << '\n';
        return 1;
      }
    }

    return 0;
  }

  if (options.mode == Mode::RemoveFile) {
    auto removed = vault->remove_file(options.file_id);
    if (!removed) {
      return fail(removed.error());
    }

    auto saved = vault->save(options.vault_path);
    if (!saved) {
      return fail(saved.error());
    }

    std::cout << "File removed, id=" << options.file_id << '\n';
    return 0;
  }

  print_usage(std::cerr);
  return 2;
}
