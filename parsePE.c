#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
char* bufExe;
char* dirName[] = {"Export Table",
                    "Import Table",
                    "Resource Table",
                    "Exception Table",
                    "Certificate Table",
                    "Base Relocation Table",
                    "Debug",
                    "Architecture",
                    "Global Ptr",
                    "TLS Table",
                    "Load Config Table",
                    "Bound Import",
                    "IAT",
                    "Delay Import Descriptor",
                    "CLR Runtime Header",
                    "Reserved"};

int parseFileHdr(IMAGE_NT_HEADERS64* ntHdr){
    IMAGE_FILE_HEADER* fileHdrExe = &ntHdr->FileHeader;
    printf("\n---------- In File Header ----------\n");
    printf("Characteristic:            %hi\n", fileHdrExe->Characteristics);
    printf("Machine:                   %hi\n", fileHdrExe->Machine);
    printf("Number of Sections:        %hi\n", fileHdrExe->NumberOfSections);
    printf("Number of Symbols:         %lu\n", fileHdrExe->NumberOfSymbols);
    printf("Pointer to Symbol Table:   0x%lx\n", fileHdrExe->PointerToSymbolTable);
    printf("Size of Optional Header:   %hi\n", fileHdrExe->SizeOfOptionalHeader);
    printf("Time Date Stamp:           %li\n", fileHdrExe->TimeDateStamp);
    return 0;
}

int parseOptHdr(IMAGE_NT_HEADERS64* ntHdr){
    IMAGE_OPTIONAL_HEADER64* optHdrExe = &ntHdr->OptionalHeader;
    printf("\n---------- In Optional Header ----------\n");
    printf("Address of EntryPoint:     0x%lx\n", optHdrExe->AddressOfEntryPoint);
    printf("Base of Code:              0x%lx\n", optHdrExe->BaseOfCode);
    printf("CheckSum:                  0x%lx\n", optHdrExe->CheckSum);
    printf("DataDirectory:             0x%s\n", "IMAGE_DATA_DIRECTORY");
    printf("DllCharacteristics:        0x%hx\n", optHdrExe->DllCharacteristics);
    printf("File Alignment:            0x%lx\n", optHdrExe->FileAlignment);
    printf("Image Base:                0x%llx\n", optHdrExe->ImageBase);
    printf("Loader Flags:              0x%lx\n", optHdrExe->LoaderFlags);
    printf("Magic:                     0x%hx\n", optHdrExe->Magic);
    printf("Major Image Version:       0x%hx\n", optHdrExe->MajorImageVersion);
    printf("Major Linker Version:      0x%hhx\n", optHdrExe->MajorLinkerVersion);
    printf("Major Operating System Version: 0x%hx\n", optHdrExe->MajorOperatingSystemVersion);
    printf("Major Subsystem Version:   0x%hx\n", optHdrExe->MajorSubsystemVersion);
    printf("Minor Image Version:       0x%hx\n", optHdrExe->MinorImageVersion);
    printf("Minor Linker Version:      0x%hhx\n", optHdrExe->MinorLinkerVersion);
    printf("Minor Operating System Version: 0x%hx\n", optHdrExe->MinorOperatingSystemVersion);
    printf("Minor Subsystem Version:   0x%hx\n", optHdrExe->MinorSubsystemVersion);
    printf("Number of RVA and Sizes:   0x%lx\n", optHdrExe->NumberOfRvaAndSizes);
    printf("Section Alignment:         0x%lx\n", optHdrExe->SectionAlignment);
    printf("Size of Code:              0x%lx\n", optHdrExe->SizeOfCode);
    printf("Size of Headers:           0x%lx\n", optHdrExe->SizeOfHeaders);
    printf("Size of Heap Commit:       0x%llx\n", optHdrExe->SizeOfHeapCommit);
    printf("Size of Heap Reserve:      0x%llx\n", optHdrExe->SizeOfHeapReserve);
    printf("Size of Image:             0x%lx\n", optHdrExe->SizeOfImage);
    printf("Size of Initialized Data:  0x%lx\n", optHdrExe->SizeOfInitializedData);
    printf("Size of Stack Commit:      0x%llx\n", optHdrExe->SizeOfStackCommit);
    printf("Size of Stack Reserve:     0x%llx\n", optHdrExe->SizeOfStackReserve);
    printf("Size of Uninitialzed Date: 0x%lx\n", optHdrExe->SizeOfUninitializedData);
    printf("Subsystem:                 0x%hx\n", optHdrExe->Subsystem);
    printf("Win32 Version Value:       0x%lx\n", optHdrExe->Win32VersionValue);

    return 0;
}

int parseSecHdr(IMAGE_NT_HEADERS64* ntHdr){
    int secNum = ntHdr->FileHeader.NumberOfSections;
    int dosLen = ((IMAGE_DOS_HEADER*)bufExe)->e_lfanew;
    IMAGE_SECTION_HEADER* secHdrExe = (IMAGE_SECTION_HEADER*) &bufExe[dosLen + sizeof(IMAGE_NT_HEADERS64)];
    printf("\n---------- In Section Header ----------\n");

    for(int i=0;i<secNum;i++){
        printf("\n---------- In %s Section ----------\n", secHdrExe[i].Name);
        printf("Virtual Address:           0x%lx\n", secHdrExe[i].VirtualAddress);
        printf("Virtual Size:              0x%lx\n", secHdrExe[i].Misc.VirtualSize);
        printf("Pointer to Raw Data:       0x%lx\n", secHdrExe[i].PointerToRawData);
        printf("Size of Raw Data:          0x%lx\n", secHdrExe[i].SizeOfRawData);
        printf("Characteristics:           0x%lx\n", secHdrExe[i].Characteristics);
        printf("Number of Line Numbers:    0x%hx\n", secHdrExe[i].NumberOfLinenumbers);
        printf("Number of Relocations:     0x%hx\n", secHdrExe[i].NumberOfRelocations);
        printf("Pointer to Line Numbers:   0x%lx\n", secHdrExe[i].PointerToLinenumbers);
        printf("Pointer to Relocation:     0x%lx\n", secHdrExe[i].PointerToRelocations);
    }

    return 0;
}

int parseDataDir(IMAGE_NT_HEADERS64* ntHdr){
    printf("\n---------- In Data Directory ----------\n");
    IMAGE_OPTIONAL_HEADER64* optHdrExe = &ntHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* dirExe = optHdrExe->DataDirectory;

    for(int i=0;i<16;i++){
        printf("%s\n", dirName[i]);
        printf("Virtual Address:           0x%lx\n", dirExe[i].VirtualAddress);
        printf("Size:                      0x%lx\n\n", dirExe[i].Size);
    }

    return 0;
}

int parseImp(IMAGE_NT_HEADERS64* ntHdr){
    int secNum = ntHdr->FileHeader.NumberOfSections;
    int dosLen = ((IMAGE_DOS_HEADER*)bufExe)->e_lfanew;
    IMAGE_SECTION_HEADER* secHdrExe = (IMAGE_SECTION_HEADER*) &bufExe[dosLen + sizeof(IMAGE_NT_HEADERS64)];

    IMAGE_OPTIONAL_HEADER64* optHdrExe = &ntHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* dirExe = optHdrExe->DataDirectory;
    DWORD impAddr = dirExe[1].VirtualAddress;
    DWORD impLen = (int)dirExe[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    
    printf("\n---------- In Tracing Imported Module ----------\n");
    for(int i=0;i<secNum;i++){
        DWORD secVirAddr = secHdrExe[i].VirtualAddress;
        DWORD secPhyAddr = secHdrExe[i].PointerToRawData;
        DWORD secVirSize = secHdrExe[i].Misc.VirtualSize;
        if(impAddr >= secVirAddr && impAddr < secVirAddr+secVirSize){
            DWORD offset = secVirAddr-secPhyAddr;
            IMAGE_IMPORT_DESCRIPTOR* importTable = (IMAGE_IMPORT_DESCRIPTOR*)&bufExe[impAddr - offset];
            for(int i=0;i<impLen-1;i++){ // impLen
                // printf("impLen: %ld\n", impLen);
                printf("\n---------- In Module %s ----------\n", &bufExe[importTable[i].Name - offset]);
                DWORD thunkIdx = importTable[i].OriginalFirstThunk;
                while(1){
                    unsigned long long nameIdx = 0;
                    for(int k=0;k<8;k++){ // 8 bytes
                        unsigned long long byt = (unsigned long long) bufExe[thunkIdx - offset + k];
                        // for(int l=0;l<k;l++) byt *= 256; // add offset
                        byt &= 0xff;
                        byt = byt << k*8;
                        nameIdx += byt;
                    }
                    // printf("u1: %llx\n", nameIdx);
                    if(nameIdx == 0) break;
                    IMAGE_IMPORT_BY_NAME* impName = (IMAGE_IMPORT_BY_NAME*)&bufExe[nameIdx-offset];
                    printf("Imported function:         %s\n", impName->Name);
                    thunkIdx += 8;
                }
            }
            return 0;
        }
    }

    return 1;
}

int main(int argc, char** argv){
    if(argc != 2){
        printf("[Usage] ./parsePE.exe executable\n");
        return 0;
    }

    FILE* fexe;
    long long int length=0;

    if((fexe = fopen(argv[1], "rb+")) == NULL){
        printf("File does not exist!\n");
    }
    fseek(fexe, 0, SEEK_END);
    length = ftell(fexe);
    rewind(fexe);
    bufExe = (char*) malloc(sizeof(char) * length);
    fread(bufExe, sizeof(char), length, fexe);
    fclose(fexe);

    IMAGE_DOS_HEADER* dosExe = (IMAGE_DOS_HEADER*) bufExe;
    IMAGE_NT_HEADERS64* ntHdr = (IMAGE_NT_HEADERS64*) &bufExe[dosExe->e_lfanew];
    // printf("%lx\n", dosExe->e_lfanew);
    printf("\n---------- In NT Header ----------\n");
    printf("Signature:                 %s\n", (char*)ntHdr);

    if(parseFileHdr(ntHdr))
        printf("[ERROR] Parse file header error!\n");
    
    if(parseOptHdr(ntHdr))
        printf("[ERROR] Parse optional header error!\n");

    if(parseSecHdr(ntHdr))
        printf("[ERROR] Parse section header error!\n");
    
    if(parseDataDir(ntHdr))
        printf("[ERROR] Parse Data Directory error!\n");

    if(parseImp(ntHdr))
        printf("[ERROR] Parse Import Table error!\n");
}