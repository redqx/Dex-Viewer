
from enum import Enum

sections_description = {
    ".bss": "Uninitialized data",
    ".comment": "Version control information",
    ".data": "Initialized data",
    ".data1": "Initialized data",
    ".debug": "Symbolic debugging information",
    ".dynamic": "Dynamic linking information",
    ".dynstr": "Dynamic linking strings",
    ".dynsym": "Dynamic linking symbol table",
    ".fini": "Process termination code",
    ".fini_array": "Termination function pointers",
    ".got": "Global offset table",
    ".hash": "Symbol hash table",
    ".init": "Process initialization code",
    ".init_array": "Initialization function pointers",
    ".interp": "Program interpreter",
    ".line": "Line number for debugging",
    ".note": "Specific vendor information",
    ".plt": "Procedure linkage table",
    ".preinit_array": "Pre-initialization functions",
    ".rel": "Relocation information,",
    ".rodata": "Read-only data",
    ".rodata1": "Read-only data",
    ".shstrtab": "Section names",
    ".strtab": "Strings (symbol table)",
    ".symtab": "Symbol table",
    ".symtab_shndx": "Special symbol table",
    ".tbss": "Uninitialized thread-local data",
    ".tdata": "Initialized thread-local data",
    ".text": "Executable instruction",
}
class RelType_X86_64(Enum): #AMD

    # AMD64
    R_X86_64_NONE = 0
    R_X86_64_64 = 1
    R_X86_64_PC32 = 2
    R_X86_64_GOT32 = 3
    R_X86_64_PLT32 = 4
    R_X86_64_COPY = 5
    R_X86_64_GLOB_DAT = 6
    R_X86_64_JUMP_SLOT = 7
    R_X86_64_RELATIVE = 8
    R_X86_64_GOTPCREL = 9

    R_X86_64_32 = 10
    R_X86_64_32S = 11
    R_X86_64_16 = 12
    R_X86_64_PC16 = 13
    R_X86_64_8 = 14
    R_X86_64_PC8 = 15
    R_X86_64_DTPMOD64 = 16
    R_X86_64_DTPOFF64 = 17
    R_X86_64_TPOFF64 = 18
    R_X86_64_TLSGD = 19

    R_X86_64_TLSLD = 20

    R_X86_64_DTPOFF32 = 21
    R_X86_64_GOTTPOFF = 22

    R_X86_64_TPOFF32 = 23
    R_X86_64_PC64 = 24
    R_X86_64_GOTOFF64 = 25
    R_X86_64_GOTPC32 = 26
    R_X86_64_GOT64 = 27
    R_X86_64_GOTPCREL64 = 28
    R_X86_64_GOTPC64 = 29
    R_X86_64_GOTPLT64 = 30
    R_X86_64_PLTOFF64 = 31
    R_X86_64_SIZE32 = 32
    R_X86_64_SIZE64 = 33

    R_X86_64_GOTPC32_TLSDESC = 34
    R_X86_64_TLSDESC_CALL = 35

    R_X86_64_TLSDESC = 36
    R_X86_64_IRELATIVE = 37
    R_X86_64_RELATIVE64 = 38
    R_X86_64_GOTPCRELX = 41
    R_X86_64_REX_GOTPCRELX = 42
    R_X86_64_NUM = 43

class RelType_386(Enum): #AMD 32
    R_386_NONE = 0
    R_386_32 = 1
    R_386_PC32 = 2
    R_386_GOT32 = 3
    R_386_PLT32 = 4
    R_386_COPY = 5
    R_386_GLOB_DAT = 6
    R_386_JMP_SLOT = 7
    R_386_RELATIVE = 8
    R_386_GOTOFF = 9
    R_386_GOTPC = 10
    R_386_32PLT = 11
    R_386_TLS_TPOFF = 14
    R_386_TLS_IE = 15
    R_386_TLS_GOTIE = 16
    R_386_TLS_LE = 17
    R_386_TLS_GD = 18
    R_386_TLS_LDM = 19
    R_386_16 = 20
    R_386_PC16 = 21
    R_386_8 = 22
    R_386_PC8 = 23
    R_386_TLS_GD_32 = 24
    R_386_TLS_GD_PUSH = 25
    R_386_TLS_GD_CALL = 26
    R_386_TLS_GD_POP = 27
    R_386_TLS_LDM_32 = 28
    R_386_TLS_LDM_PUSH = 29
    R_386_TLS_LDM_CALL = 30
    R_386_TLS_LDM_POP = 31
    R_386_TLS_LDO_32 = 32
    R_386_TLS_IE_32 = 33
    R_386_TLS_LE_32 = 34
    R_386_TLS_DTPMOD32 = 35
    R_386_TLS_DTPOFF32 = 36
    R_386_TLS_TPOFF32 = 37
    R_386_SIZE32 = 38
    R_386_TLS_GOTDESC = 39
    R_386_TLS_DESC_CALL = 40
    R_386_TLS_DESC = 41
    R_386_IRELATIVE = 42
    R_386_GOT32X = 43
    R_386_NUM = 44
class _ConstType(int):
    """
    This class is an integer mm_type with usage
    and description attributes.
    """

    def __new__(cls, value: int, usage: str="", description: str=""):
        self = int.__new__(cls, value)
        self.usage = usage
        self.description = description
        return self

class DynamicType(Enum):
    # elf.h 中有完整的定义, 这里并不完整,完整也不一定好
    DT_NULL = _ConstType(0, "ignored", "End of dynamic array")
    DT_NEEDED = _ConstType(1, "value", "Needed library name offset")
    DT_PLTRELSZ = _ConstType(2, "value", "Relocation entries size")
    DT_PLTGOT = _ConstType(3, "pointer", "Address procedure linkage table")
    DT_HASH = _ConstType(4, "pointer", "Address symbol hash table")
    DT_STRTAB = _ConstType(5, "pointer", "Address string table (.dynstr)")
    DT_SYMTAB = _ConstType(6, "pointer", "Address symbol table (.dynsym)")
    DT_RELA = _ConstType(7, "pointer", "Address relocation table")
    DT_RELASZ = _ConstType(8, "value", "Relocation table size")
    DT_RELAENT = _ConstType(9, "value", "Relocation entry size")
    DT_STRSZ = _ConstType(10, "value", "String table size")
    DT_SYMENT = _ConstType(11, "value", "Symbol table entry size")
    DT_INIT = _ConstType(12, "pointer", "Initialization function address")
    DT_FINI = _ConstType(13, "pointer", "Termination function address")
    DT_SONAME = _ConstType(14, "value", "Shared object name")
    DT_RPATH = _ConstType(15, "value", "Library search path string")
    DT_SYMBOLIC = _ConstType(16, "ignored", "Alters dynamic linker's symbol")
    DT_REL = _ConstType(17, "pointer", "Address relocation table")
    DT_RELSZ = _ConstType(18, "value", "Relocation table size")
    DT_RELENT = _ConstType(19, "value", "Relocation entry size")
    DT_PLTREL = _ConstType(20, "value", "Relocation entry mm_type")
    DT_DEBUG = _ConstType(21, "pointer", "Used for debugging")
    DT_TEXTREL = _ConstType(22, "ignored", "No relocation on non-writable segment")
    DT_JMPREL = _ConstType(23, "pointer", "Procedure linkage table")
    DT_BIND_NOW = _ConstType(24, "ignored", "Relocations before execution")
    DT_INIT_ARRAY = _ConstType(25, "pointer", "Initialization functions pointers")
    DT_FINI_ARRAY = _ConstType(26, "pointer", "Termination functions pointers")
    DT_INIT_ARRAYSZ = _ConstType(27, "value", "Initialization functions number")
    DT_FINI_ARRAYSZ = _ConstType(28, "value", "Termination functions number")
    DT_RUNPATH = _ConstType(29, "value", "Library search path")
    DT_FLAGS = _ConstType(30, "value", "Flag values specific")
    DT_ENCODING = _ConstType(32, "unspecified", "Values interpretation rules")
    DT_PREINIT_ARRAY = _ConstType(32, "pointer", "Pre-initialization functions")
    DT_PREINIT_ARRAYSZ = _ConstType(33, "value", "Pre-init functions size")

    # add
    DT_LOOS = 0x6000000d
    DT_HIOS = 0x6ffff000
    DT_LOPROC = 0x70000000
    DT_HIPROC = 0x7fffffff
    DT_VALRNGLO = 0x6ffffd00
    DT_GNU_PRELINKED = 0x6ffffdf5
    DT_GNU_CONFLICTSZ =0x6ffffdf6
    DT_GNU_LIBLISTSZ = 0x6ffffdf7
    DT_CHECKSUM = 0x6ffffdf8
    DT_PLTPADSZ = 0x6ffffdf9
    DT_MOVEENT = 0x6ffffdfa
    DT_MOVESZ = 0x6ffffdfb
    DT_FEATURE_1 = 0x6ffffdfc
    DT_POSFLAG_1 = 0x6ffffdfd
    DT_SYMINSZ = 0x6ffffdfe
    DT_SYMINENT = 0x6ffffdff
    DT_VALRNGHI = 0x6ffffdff
    DT_ADDRRNGLO = 0x6ffffe00
    DT_GNU_HASH = 0x6ffffef5
    DT_TLSDESC_PLT = 0x6ffffef6
    DT_TLSDESC_GOT = 0x6ffffef7
    DT_GNU_CONFLICT = 0x6ffffef8
    DT_GNU_LIBLIST = 0x6ffffef9
    DT_CONFIG = 0x6ffffefa
    DT_DEPAUDIT = 0x6ffffefb
    DT_AUDIT = 0x6ffffefc
    DT_PLTPAD = 0x6ffffefd
    DT_MOVETAB = 0x6ffffefe
    DT_SYMINFO = 0x6ffffeff
    DT_ADDRRNGHI = 0x6ffffeff
    DT_VERSYM = 0x6ffffff0
    DT_RELACOUNT = 0x6ffffff9
    DT_RELCOUNT = 0x6ffffffa
    DT_FLAGS_1 = 0x6ffffffb
    DT_VERDEF = 0x6ffffffc
    DT_VERDEFNUM = 0x6ffffffd
    DT_VERNEED = 0x6ffffffe
    DT_VERNEEDNUM = 0x6fffffff
    DT_AUXILIARY = 0x7ffffffd
    DT_FILTER = 0x7fffffff



class DynamicFlags(Enum):
    DF_ORIGIN = _ConstType(0x1, description="Load libraries using filepath")
    DF_SYMBOLIC = _ConstType(0x2, description="Link start with object itself")
    DF_TEXTREL = _ConstType(0x4, description="No relocation on non-writable segment")
    DF_BIND_NOW = _ConstType(0x8, description="Relocations before execution")
    DF_STATIC_TLS = _ConstType(0x10, description="This object can't be link")

class SectionGroupFlags(Enum):
    GRP_COMDAT = 0x1
    GRP_MASKOS = 0x0FF00000
    GRP_MASKPROC = 0xF0000000


class SymbolBinding(Enum):
    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2
    STB_LOOS = 10
    STB_HIOS = 12
    STB_LOPROC = 13
    STB_HIPROC = 15


class SymbolType(Enum):
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6
    STT_NUM = 7
    STT_LOOS = 10
    STT_GNU_IFUNC = 10
    STT_HIOS = 12
    STT_LOPROC = 13
    STT_HIPROC = 15
class SectionAttributeFlags(Enum):
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MERGE = 0x10
    SHF_STRINGS = 0x20
    SHF_INFO_LINK = 0x40
    SHF_LINK_ORDER = 0x80
    SHF_OS_NONCONFORMING = 0x100
    SHF_GROUP = 0x200
    SHF_TLS = 0x400
    SHF_MASKOS = 0x0FF00000
    SHF_MASKPROC = 0xF0000000

class SectionHeaderType(Enum):
    # from 010editor elf.bt
    SHT_NULL = 0x0  #, /* Inactive section header */
    SHT_PROGBITS = 0x1  #, /* Information defined by the program */
    SHT_SYMTAB = 0x2  #, /* Symbol table - not DLL */
    SHT_STRTAB = 0x3  #, /* String table */
    SHT_RELA = 0x4  #, /* Explicit addend relocations, Elf64_Rela */
    SHT_HASH = 0x5  #, /* Symbol hash table */
    SHT_DYNAMIC = 0x6  #, /* Information for dynamic linking */
    SHT_NOTE = 0x7  #, /* A Note section */
    SHT_NOBITS = 0x8  #, /* Like SHT_PROGBITS with no data */
    SHT_REL = 0x9  #, /* Implicit addend relocations, Elf64_Rel */
    SHT_SHLIB = 0xA  #, /* Currently unspecified semantics */
    SHT_DYNSYM = 0xB  #, /* Symbol table for a DLL */
    SHT_INIT_ARRAY = 0xE  #, /* Array of constructors */
    SHT_FINI_ARRAY = 0xF  #, /* Array of deconstructors */
    SHT_PREINIT_ARRAY = 0x10  #, /* Array of pre-constructors */
    SHT_GROUP = 0x11  #, /* Section group */
    SHT_SYMTAB_SHNDX = 0x12  #, /* Extended section indeces */
    SHT_NUM = 0x13  #, /* Number of defined types */
    SHT_LOOS = 0x60000000  #, /* Lowest OS-specific section mm_type */
    SHT_GNU_ATTRIBUTES = 0x6ffffff5  #, /* Object attribuytes */
    SHT_GNU_HASH = 0x6ffffff6  #, /* GNU-style hash table */
    SHT_GNU_LIBLIST = 0x6ffffff7  #, /* Prelink library list */
    SHT_CHECKSUM = 0x6ffffff8  #, /* Checksum for DSO content */
    SHT_LOSUNW = 0x6ffffffa  #, /* Sun-specific low bound */
    SHT_SUNW_move = 0x6ffffffa  #, // Same thing
    SHT_SUNW_COMDAT = 0x6ffffffb  #,
    SHT_SUNW_syminfo = 0x6ffffffc  #,
    SHT_GNU_verdef = 0x6ffffffd  #, /* Version definition section */
    SHT_GNU_verdneed = 0x6ffffffe  #, /* Version needs section */
    SHT_GNU_versym = 0x6fffffff  #, /* Version symbol table */
    SHT_HISUNW = 0x6fffffff  #, /* Sun-specific high bound */
    SHT_HIOS = 0x6fffffff  #, /* Highest OS-specific section mm_type */
    SHT_LOPROC = 0x70000000  #, /* Start of processor-specific section mm_type */
    SHT_HIPROC = 0x7fffffff  #, /* End of processor-specific section mm_type */
    SHT_LOUSER = 0x80000000  #, /* Start of application-specific */
    SHT_HIUSER = 0x8fffffff  # /* Ennd of application-specific */

class ProgramHeaderFlags(Enum):
    # PF_EXECUTE = 1
    # PF_WRITE = 2
    # PF_READ = 3
    # PF_MASKOS = 0x0FF00000
    # PF_MASKPROC = 0xF0000000
    PF_X = (1 << 0)  #/* Segment is executable */
    PF_W = (1 << 1)  #/* Segment is writable */
    PF_R = (1 << 2)  #/* Segment is readable */
    PF_MASKOS = 0x0ff00000  #/* OS-specific */
    PF_MASKPROC = 0xf0000000  #/* Processor-specific */

class ProgramHeaderType(Enum):
    # from 010editor elf.bt
    PT_NULL = 0x0
    PT_LOAD = 0x1
    PT_DYNAMIC = 0x2
    PT_INTERP = 0x3
    PT_NOTE = 0x4
    PT_SHLIB = 0x5
    PT_PHDR = 0x6
    PT_TLS = 0x7
    PT_NUM = 0x8
    PT_LOOS = 0x60000000
    PT_GNU_EH_FRAME = 0x6474e550
    PT_GNU_STACK = 0x6474e551
    PT_GNU_RELRO = 0x6474e552
    PT_GNU_PROPERTY = 0x6474e553
    PT_LOSUNW = 0x6ffffffa
    PT_SUNWBSS = 0x6ffffffa
    PT_SUNWSTACK = 0x6ffffffb
    PT_HISUNW = 0x6fffffff
    PT_HIOS = 0x6fffffff
    PT_LOPROC = 0x70000000
    PT_HIPROC = 0x7fffffff
    # ARM Sections
    PT_SHT_ARM_EXIDX = 0x70000001
    PT_SHT_ARM_PREEMPTMAP = 0x70000002
    PT_SHT_ARM_ATTRIBUTES = 0x70000003
    PT_SHT_ARM_DEBUGOVERLAY = 0x70000004
    PT_SHT_ARM_OVERLAYSECTION = 0x70000005
class SpecialSectionIndexes(Enum):
    SHN_UNDEF = 0
    SHN_LOPROC = SHN_LORESERVE = 0xFF00
    SHN_HIPROC = 0xFF1F
    SHN_LOOS = 0xFF20
    SHN_HIOS = 0xFF3F
    SHN_ABS = 0xFFF1
    SHN_COMMON = 0xFFF2
    SHN_HIRESERVE = SHN_XINDEX = 0xFFFF
class ElfMachine(Enum):
    # android external/musl/include/elf.h
    EM_NONE = 0
    EM_M32 = 1
    EM_SPARC = 2
    EM_386 = 3
    EM_68K = 4
    EM_88K = 5
    EM_860 = 7
    EM_MIPS = 8
    EM_S370 = 9
    EM_MIPS_RS3_LE = 10
    EM_PARISC = 15
    EM_VPP500 = 17
    EM_SPARC32PLUS = 18
    EM_960 = 19
    EM_PPC = 20
    EM_PPC64 = 21
    EM_S390 = 22
    EM_V800 = 36
    EM_FR20 = 37
    EM_RH32 = 38
    EM_RCE = 39
    EM_ARM = 40
    EM_FAKE_ALPHA = 41
    EM_SH = 42
    EM_SPARCV9 = 43
    EM_TRICORE = 44
    EM_ARC = 45
    EM_H8_300 = 46
    EM_H8_300H = 47
    EM_H8S = 48
    EM_H8_500 = 49
    EM_IA_64 = 50
    EM_MIPS_X = 51
    EM_COLDFIRE = 52
    EM_68HC12 = 53
    EM_MMA = 54
    EM_PCP = 55
    EM_NCPU = 56
    EM_NDR1 = 57
    EM_STARCORE = 58
    EM_ME16 = 59
    EM_ST100 = 60
    EM_TINYJ = 61
    EM_X86_64 = 62
    EM_PDSP = 63
    EM_FX66 = 66
    EM_ST9PLUS = 67
    EM_ST7 = 68
    EM_68HC16 = 69
    EM_68HC11 = 70
    EM_68HC08 = 71
    EM_68HC05 = 72
    EM_SVX = 73
    EM_ST19 = 74
    EM_VAX = 75
    EM_CRIS = 76
    EM_JAVELIN = 77
    EM_FIREPATH = 78
    EM_ZSP = 79
    EM_MMIX = 80
    EM_HUANY = 81
    EM_PRISM = 82
    EM_AVR = 83
    EM_FR30 = 84
    EM_D10V = 85
    EM_D30V = 86
    EM_V850 = 87
    EM_M32R = 88
    EM_MN10300 = 89
    EM_MN10200 = 90
    EM_PJ = 91
    EM_OR1K = 92
    EM_OPENRISC = 92
    EM_ARC_A5 = 93
    EM_ARC_COMPACT = 93
    EM_XTENSA = 94
    EM_VIDEOCORE = 95
    EM_TMM_GPP = 96
    EM_NS32K = 97
    EM_TPC = 98
    EM_SNP1K = 99
    EM_ST200 = 100
    EM_IP2K = 101
    EM_MAX = 102
    EM_CR = 103
    EM_F2MC16 = 104
    EM_MSP430 = 105
    EM_BLACKFIN = 106
    EM_SE_C33 = 107
    EM_SEP = 108
    EM_ARCA = 109
    EM_UNICORE = 110
    EM_EXCESS = 111
    EM_DXP = 112
    EM_ALTERA_NIOS2 = 113
    EM_CRX = 114
    EM_XGATE = 115
    EM_C166 = 116
    EM_M16C = 117
    EM_DSPIC30F = 118
    EM_CE = 119
    EM_M32C = 120
    EM_TSK3000 = 131
    EM_RS08 = 132
    EM_SHARC = 133
    EM_ECOG2 = 134
    EM_SCORE7 = 135
    EM_DSP24 = 136
    EM_VIDEOCORE3 = 137
    EM_LATTICEMICO32 = 138
    EM_SE_C17 = 139
    EM_TI_C6000 = 140
    EM_TI_C2000 = 141
    EM_TI_C5500 = 142
    EM_TI_ARP32 = 143
    EM_TI_PRU = 144
    EM_MMDSP_PLUS = 160
    EM_CYPRESS_M8C = 161
    EM_R32C = 162
    EM_TRIMEDIA = 163
    EM_QDSP6 = 164
    EM_8051 = 165
    EM_STXP7X = 166
    EM_NDS32 = 167
    EM_ECOG1X = 168
    EM_MAXQ30 = 169
    EM_XIMO16 = 170
    EM_MANIK = 171
    EM_CRAYNV2 = 172
    EM_RX = 173
    EM_METAG = 174
    EM_MCST_ELBRUS = 175
    EM_ECOG16 = 176
    EM_CR16 = 177
    EM_ETPU = 178
    EM_SLE9X = 179
    EM_L10M = 180
    EM_K10M = 181
    EM_AARCH64 = 183
    EM_AVR32 = 185
    EM_STM8 = 186
    EM_TILE64 = 187
    EM_TILEPRO = 188
    EM_MICROBLAZE = 189
    EM_CUDA = 190
    EM_TILEGX = 191
    EM_CLOUDSHIELD = 192
    EM_COREA_1ST = 193
    EM_COREA_2ND = 194
    EM_ARC_COMPACT2 = 195
    EM_OPEN8 = 196
    EM_RL78 = 197
    EM_VIDEOCORE5 = 198
    EM_78KOR = 199
    EM_56800EX = 200
    EM_BA1 = 201
    EM_BA2 = 202
    EM_XCORE = 203
    EM_MCHP_PIC = 204
    EM_KM32 = 210
    EM_KMX32 = 211
    EM_EMX16 = 212
    EM_EMX8 = 213
    EM_KVARC = 214
    EM_CDP = 215
    EM_COGE = 216
    EM_COOL = 217
    EM_NORC = 218
    EM_CSR_KALIMBA = 219
    EM_Z80 = 220
    EM_VISIUM = 221
    EM_FT32 = 222
    EM_MOXIE = 223
    EM_AMDGPU = 224
    EM_RISCV = 243
    EM_BPF = 247
    EM_CSKY = 252
    EM_NUM = 253
    EM_ALPHA = 0x9026

class ElfType(Enum):
    NO_FILE_TYPE = 0
    RELOCATABLE = 1
    EXECUTABLE = 2
    SHARED_OBJECT = 3
    CORE = 4
    OS_SPECIFIC_LOOS = 0xFE00
    OS_SPECIFIC_HIOS = 0xFEFF
    PROCESSOR_SPECIFIC_LOPROC = 0xFF00
    PROCESSOR_SPECIFIC_HIPROC = 0xFFFF
class ELfIdentVersion(Enum):
    INVALID = 0
    CURRENT = 1
class ELfIdentOS(Enum):
    SYSV = NONE = 0
    HPUX = 1
    NETBSD = 2
    LINUX = 3
    SOLARIS = 6
    AIX = 7
    IRIX = 8
    FREEBSD = 9
    TRU64 = 10
    MODESTO = 11
    OPENBSD = 12
    OPENVMS = 13
    NSK = 14
    AROS = 15
    ARM = 97
    MSP = 255
class ELfIdentData(Enum):
    # INVALID = 0
    # LITTLE_ENDIAN = 1
    # BIG_ENDIAN = 2
    EI_DATA = 5  #/* Data encoding byte index */
    ELFDATANONE = 0  #/* Invalid data encoding */
    ELFDATA2LSB = 1  #/* 2's complement, little endian */
    ELFDATA2MSB = 2  #/* 2's complement, big endian */
    ELFDATANUM = 3
class ELfIdentClass(Enum):
    #     INVALID = 0
    #     OBJECT_32_BITS = 1
    #     OBJECT_64_BITS = 2
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    ELFCLASSNUM = 3
    EI_CLASS = 4

class SymbolVisibility(Enum):
    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3
