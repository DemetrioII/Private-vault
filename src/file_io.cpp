#include <fcntl.h>
#include <file_io.hpp>
#include <file_table.hpp>
#include <sys/unistd.h>

FileIO::FileIO(int fd, FileEntry &file_entry)
    : fd_(fd), file_entry_(file_entry) {}

FileIO::~FileIO() { ::close(fd_); }
