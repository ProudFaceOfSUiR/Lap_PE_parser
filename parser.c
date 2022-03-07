#include "parser.h"


enum read_status parse(FILE* in, FILE* out, FILE * out2) {

    struct IMAGE_DOS_HEADER dos_header = {0};//malloc(sizeof(struct bmp_header));
    struct IMAGE_NT_HEADERS64 imageNtHeaders64 = {0};
    struct IMAGE_SECTION_HEADER imageSectionHeader = {0};
    if (fread(&dos_header, sizeof(struct IMAGE_DOS_HEADER), 1, in) == 1){
        fprintf(out, "Magic number: %c%c\n",dos_header.e_magic,dos_header.e_magic>>8);
        fprintf(out,"Bytes in last page: %hu \n", dos_header.e_cblp);
        fprintf(out,"Pages in file: %hu \n", dos_header.e_cp);
        fprintf(out,"Relocations: %hu \n", dos_header.e_crlc);
        fprintf(out,"Size of header in paragraphs: %hu \n", dos_header.e_cparhdr);
        fprintf(out,"Minimum extra paragraphs needed: %hu \n", dos_header.e_minalloc);
        fprintf(out,"Maximum extra paragraphs needed: %hu \n", dos_header.e_maxalloc);
        fprintf(out,"Initial (relative) SS value: %hu \n", dos_header.e_ss);
        fprintf(out,"Initial SP value: 0x%x \n", dos_header.e_sp);
        fprintf(out,"Address of relocation table: 0x%x \n", dos_header.e_lfarlc);
        fprintf(out,"PE header offset: 0x%x \n\n", dos_header.e_lfanew);
        //printf("%c",dos_header.e_magic>>8);
        uint16_t check = 0;
        //printf("Bytes in last page: %"PRIu16,dos_header.e_cblp);
        printf("\n");
        fseek(in,dos_header.e_lfanew,SEEK_SET);
        if(fread(&imageNtHeaders64, sizeof(struct IMAGE_NT_HEADERS64), 1, in)==1) {

            fprintf(out, "Machine %x\n", imageNtHeaders64.imageFileHeader.Machine);
            fprintf(out, "NumberOfSections %x\n", imageNtHeaders64.imageFileHeader.NumberOfSections);
            fprintf(out, "TimeDateStamp %x\n", imageNtHeaders64.imageFileHeader.TimeDateStamp);
            fprintf(out, "PointerToSymbolTable %x\n", imageNtHeaders64.imageFileHeader.PointerToSymbolTable);
            fprintf(out, "NumberOfSymbols %x\n", imageNtHeaders64.imageFileHeader.NumberOfSymbols);
            fprintf(out, "SizeOfOptionalHeader %x\n", imageNtHeaders64.imageFileHeader.SizeOfOptionalHeader);
            fprintf(out, "Characteristics %x\n", imageNtHeaders64.imageFileHeader.Characteristics);

            fprintf(out,"Optional/Image header\n");
            fprintf(out, "Magic %x\n",imageNtHeaders64.optionalHeader64.Magic);
            fprintf(out,"MajorLinkerVersion %x\n",imageNtHeaders64.optionalHeader64.MajorLinkerVersion);
            fprintf(out, "MinorLinkerVersion %x\n",imageNtHeaders64.optionalHeader64.MinorLinkerVersion);
            fprintf(out, "SizeOfInitializedData %x\n",imageNtHeaders64.optionalHeader64.SizeOfInitializedData);
            fprintf(out, "SizeOfUninitializedData %x\n",imageNtHeaders64.optionalHeader64.SizeOfUninitializedData);
            fprintf(out,"\n");
            fprintf(out, "Entrypoint %x\n",imageNtHeaders64.optionalHeader64.AddressOfEntryPoint);
            printf("\n%x\n",imageNtHeaders64.optionalHeader64.SizeOfImage);
            printf("%x\n",imageNtHeaders64.optionalHeader64.DllCharacteristics);
            printf("\n");
            printf("%x\n",imageNtHeaders64.optionalHeader64.SizeOfStackReserve);
            printf("%x\n",imageNtHeaders64.optionalHeader64.SizeOfStackCommit);
            printf("%x\n",imageNtHeaders64.optionalHeader64.SizeOfHeapReserve);
            printf("%x\n",imageNtHeaders64.optionalHeader64.SizeOfHeapCommit);
        }
        struct IMAGE_SECTION_HEADER * imageSectionHeader1 = malloc(sizeof(struct IMAGE_SECTION_HEADER)*imageNtHeaders64.imageFileHeader.NumberOfSections);

        //fseek(in,128+imageNtHeaders64.imageFileHeader.SizeOfOptionalHeader,SEEK_SET);
        for (int i = 0; i < imageNtHeaders64.imageFileHeader.NumberOfSections;++i){
            fread(&imageSectionHeader1[i], sizeof(struct IMAGE_SECTION_HEADER), 1, in);
            fprintf(out,"Name %s\n",imageSectionHeader1[i].Name);
            fprintf(out,"VirtualSize %x\n",imageSectionHeader1[i].VirtualSize);
            fprintf(out,"VirtualAddress %x\n",imageSectionHeader1[i].VirtualAddress);
            fprintf(out,"SizeOfRawData %x\n",imageSectionHeader1[i].SizeOfRawData);
            fprintf(out,"NumberOfRelocations %x\n",imageSectionHeader1[i].NumberOfRelocations);
            fprintf(out,"Characteristics %x\n",imageSectionHeader1[i].Characteristics);
            fprintf(out,"\n");
        }
        printf("\n");

        size_t sz = 0;
        uint8_t *data = {0};
        size_t size_of_file = 0;
        for (size_t i = 0; i < imageNtHeaders64.imageFileHeader.NumberOfSections;++i) {
            size_of_file+=imageSectionHeader1[i].SizeOfRawData;
        }
        printf("%zu\n",size_of_file);
        data = malloc(size_of_file*sizeof (uint8_t));
        for (size_t i = 0; i < imageNtHeaders64.imageFileHeader.NumberOfSections;++i){
            fseek(out2,imageSectionHeader1[i].PointerToRawData,SEEK_SET);
            fread(data,imageSectionHeader1[i].SizeOfRawData,1,in);
        }
        printf("%"PRIu8,data[1]);
        fwrite(data, size_of_file,1,out2);


        return ITS_PE_FILE;
    } else return ITS_NOT_PE_FILE;

}

