#ifndef _LIBUNWINDSTACK_COFF_H
#define _LIBUNWINDSTACK_COFF_H

#include <array>
#include <memory>
#include <mutex>
#include <vector>

#include <unwindstack/Error.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

// Forward declaration.
struct MapInfo;
class Regs;

struct DosHeader {
  uint16_t magic;
  // 29 * uint16_t fields
  uint32_t lfanew;  // Naming from lldb code.
};

struct CoffHeader {
  uint16_t machine;
  uint16_t nsects;
  uint16_t hdrsize;
};

struct DataDirectory {
  uint32_t vmaddr;
  uint32_t vmsize;
};

struct CoffOptionalHeader {
  uint16_t magic = 0;
  uint8_t major_linker_version = 0;
  uint8_t minor_linker_version = 0;
  uint32_t code_size = 0;
  uint32_t data_size = 0;
  uint32_t bss_size = 0;
  uint32_t entry = 0;
  uint32_t code_offset = 0;
  uint32_t data_offset = 0;
  uint64_t image_base = 0;
  uint32_t sect_alignment = 0;
  uint32_t file_alignment = 0;
  uint16_t major_os_system_version = 0;
  uint16_t minor_os_system_version = 0;
  uint16_t major_image_version = 0;
  uint16_t minor_image_version = 0;
  uint16_t major_subsystem_version = 0;
  uint16_t minor_subsystem_version = 0;
  uint32_t reserved1 = 0;
  uint32_t image_size = 0;
  uint32_t header_size = 0;
  uint32_t checksum = 0;
  uint16_t subsystem = 0;
  uint16_t dll_flags = 0;
  uint64_t stack_reserve_size = 0;
  uint64_t stack_commit_size = 0;
  uint64_t heap_reserve_size = 0;
  uint64_t heap_commit_size = 0;
  uint32_t loader_flags = 0;
  uint32_t num_data_dir_entries;
  std::vector<DataDirectory> data_dirs;  // will contain num_data_dir_entries entries
};

struct SectionHeader {
  std::array<char, 8> name;
  uint32_t vmsize;
  uint32_t vmaddr;
  uint32_t size;
  uint32_t offset;
  uint32_t reloff;
  uint32_t lineoff;
  uint16_t nrel;
  uint16_t nline;
  uint32_t flags;
};

struct Section {
  std::string name;
  uint32_t vmsize;
  uint32_t vmaddr;
  uint32_t size;    // Size in file
  uint32_t offset;  // Offset in file
};

union UnwindCode {
  struct {
    uint8_t code_offset;
    uint8_t unwind_op_and_op_info;
  } code_and_op;
  uint16_t frame_offset;

  uint8_t GetUnwindOp() const { return code_and_op.unwind_op_and_op_info & 0x0f; }
  uint8_t GetOpInfo() const { return (code_and_op.unwind_op_and_op_info >> 4) & 0x0f; }
};

// Data from RUNTIME_FUNCTION array.
// https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160#struct-runtime_function
struct RuntimeFunction {
  uint32_t start_address;
  uint32_t end_address;
  uint32_t unwind_info_offset;
};

// UNWIND_INFO struct
// https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160#struct-unwind_info
struct UnwindInfo {
  // First 3 bits are the version, other 5 bits are the flags.
  uint8_t version_and_flags;
  uint8_t prolog_size;
  uint8_t num_codes;
  // First 4 bits frame register, second 4 bits frame register offset.
  uint8_t frame_register_and_offset;
  std::vector<UnwindCode> unwind_codes;

  // TODO: There's potentially more data after the unwind codes, which can be either a language
  // specific exception handler or chained unwind info (which we have to follow in case it exists).

  uint8_t GetVersion() const { return version_and_flags & 0x07; }

  uint8_t GetFlags() const { return (version_and_flags >> 3) & 0x1f; }

  uint8_t GetFrameRegister() const { return frame_register_and_offset & 0x0f; }

  uint8_t GetFrameOffset() const { return (frame_register_and_offset >> 4) & 0x0f; }
};

class Coff {
 public:
  Coff(Memory* memory) : memory_(memory) {}
  virtual ~Coff() = default;

  bool Init();

  /*
  bool StepIfSignalHandler(uint64_t rel_pc, Regs* regs, Memory* process_memory);
  */
  bool Step(uint64_t rel_pc, Regs* regs, Memory* process_memory, bool* finished);

  int64_t GetLoadBias() { return load_bias_; }

  bool IsValidPc(uint64_t pc);

  void GetLastError(ErrorData* data);
  ErrorCode GetLastErrorCode();
  uint64_t GetLastErrorAddress();

  Memory* memory() { return memory_.get(); }

 protected:
  bool ParseSectionHeaders(const CoffHeader& coff_header, Memory* memory, uint64_t* offset);
  void InitializeSections();
  bool ParseHeaders(Memory* memory);
  bool ParseExceptionTableExperimental(Memory* object_file_memory, Memory* process_memory,
                                       Regs* regs, uint64_t pc_rva);
  bool ProcessUnwindOpCodes(Memory* process_memory, Regs* regs, const UnwindInfo& unwind_info,
                            uint64_t current_code_offset);

  int64_t load_bias_ = 0;
  std::unique_ptr<Memory> memory_;

  // Parsed data
  std::vector<SectionHeader> section_headers_;
  DosHeader dos_header_;
  CoffHeader coff_header_;
  CoffOptionalHeader coff_optional_header_;

  // Initialized from parsed data
  std::vector<Section> sections_;
  Section pdata_section_;
  Section xdata_section_;

  // Protect calls that can modify internal state of the interface object.
  std::mutex lock_;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_ELF_H
