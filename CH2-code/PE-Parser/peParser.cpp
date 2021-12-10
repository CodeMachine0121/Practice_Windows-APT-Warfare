// ConsoleApplication1.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <stdio.h>
#include <Windows.h>
#include <ctype.h>
char* readFile(const char*);
void peParser(char*);

int main(int argc, char* argv[]) {
	auto fileName = argv[1];
	//printf("%s\n", (fileName));
	auto ptrToPEBinary = readFile(argv[1]);
	peParser(ptrToPEBinary);
	return 0;
}

char *readFile(const char* fileName)
{
	
	FILE* file;
	file = fopen(fileName, "rb");
	
	/* Get the number of bytes */
	fseek(file, 0L, SEEK_END); // move to the end of file
	auto numbytes = ftell(file); // get current address of file
	
	/* reset the file position indicator to
	the beginning of the file */
	fseek(file, 0L, SEEK_SET);

	char* ptrToPEBinary = (char*)calloc(numbytes, sizeof(char)); // use to save .exe file
	
	fread(ptrToPEBinary, sizeof(char), numbytes, file);

	return ptrToPEBinary;
}

// static PE Parser
void peParser(char* ptrToPEBinary) {
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)ptrToPEBinary;
	IMAGE_NT_HEADERS* ntHdrs = (IMAGE_NT_HEADERS*)((size_t)dosHdr + dosHdr -> e_lfanew);

	// check header signature
	if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
		puts("[!] PE binary broken or invalid?");
		return;
	}

	// display information of optional header
	if (auto optHdr = &ntHdrs->OptionalHeader) {
		printf("[+] ImageBase prefer @ %p\n", optHdr->ImageBase);
		printf("[+] Dynamic Memory Usage: %x bytes.\n", optHdr->SizeOfImage);
		printf("[+] Dynamic EntryPoint @ %p\n", optHdr->ImageBase + optHdr->AddressOfEntryPoint);
	}

	// enumerate section data
	puts("[+] Section Info");
	IMAGE_SECTION_HEADER* sectHdr = (IMAGE_SECTION_HEADER*)((size_t)ntHdrs + sizeof(*ntHdrs));
	for (size_t i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++) {
		// run through all sections
		printf("\t#%.2x - %8s -%.8x - %.8x \n", i, \
			sectHdr[i].Name, sectHdr[i].PointerToRawData, sectHdr[i].SizeOfRawData);
	}
}	