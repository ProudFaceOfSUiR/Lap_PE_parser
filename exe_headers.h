//
// Created by Anatoly Novikov on 1/27/22.
//
#include <stdio.h>
#include <stdlib.h>
struct __attribute__((packed))IMAGE_DOS_HEADER
{
    uint16_t e_magic;	// 0x5A4D	"MZ"
    uint16_t e_cblp;		// 0x0080	128
    uint16_t e_cp;		// 0x0001	1
    uint16_t e_crlc;
    uint16_t e_cparhdr;	// 0x0004	4
    uint16_t e_minalloc;	// 0x0010	16
    uint16_t e_maxalloc;	// 0xFFFF	65535
    uint16_t e_ss;
    uint16_t e_sp;		// 0x0140	320
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;	// 0x0040	64
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;	// 0x0080	128
};

struct __attribute__((packed))IMAGE_FILE_HEADER
{uint16_t Machine;	// 0x8664 архитектура x86-64
    uint16_t NumberOfSections;	// 0x03 Количество секций в файле
    uint32_t TimeDateStamp	;	// Дата создания файла
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader; // Размер IMAGE_OPTIONAL_HEADER64 (Ниже)
    uint16_t Characteristics;	// 0x2F
};

struct __attribute__((packed))IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct __attribute__((packed))IMAGE_OPTIONAL_HEADER64
{uint16_t Magic;	// 0x020B Указывает что наш заголовок для PE64
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;	// 0x1000
    uint32_t BaseOfCode;	// 0x1000
    uint64_t ImageBase;	// 0x400000
    uint32_t SectionAlignment;	// 0x1000 (4096 байт)
    uint32_t FileAlignment;	// 0x200
    uint16_t MajorOperatingSystemVersion;	// 0x05	Windows XP
    uint16_t MinorOperatingSystemVersion;	// 0x02	Windows XP
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;	// 0x05	Windows XP
    uint16_t MinorSubsystemVersion;	// 0x02	Windows XP
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;	// 0x4000
    uint32_t SizeOfHeaders; // 0x200 (512 байт)
    uint32_t CheckSum;
    uint16_t Subsystem;	// 0x02 (GUI) или 0x03 (Console)
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;	// 0x100000
    uint32_t SizeOfStackCommit;	// 0x1000
    uint32_t SizeOfHeapReserve;	// 0x100000
    uint32_t SizeOfHeapCommit;	// 0x1000
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes; // 0x16
    struct IMAGE_DATA_DIRECTORY imageDataDirectory[16];

};



struct __attribute__((packed))IMAGE_NT_HEADERS64
{
    uint32_t Signature;	// 0x4550 "PE"
    struct IMAGE_FILE_HEADER imageFileHeader;
    struct IMAGE_OPTIONAL_HEADER64 optionalHeader64;

};
struct __attribute__((packed)) IMAGE_SECTION_HEADER
{
    int8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};