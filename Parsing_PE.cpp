//#include "stdAfx.h"
#include <Windows.h>
#include <iostream>
#include <stdio.h>
using namespace std;


int main() {
	const int MAX_FILEPATH = 255;
	char fileName[MAX_FILEPATH] = { "C:\\Windows\\System32\\notepad.exe" };
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER  dosHeader = {};
	//PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	//IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	// open file
	file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		std::cerr << "Could not read file" << std::endl;
		return 1; // Exit if the file could not be opened
	}

	// allocate heap
	fileSize = GetFileSize(file, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		std::cerr << "Could not get file size" << std::endl;
		CloseHandle(file);
		return 1;
	}

	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	if (!fileData) {
		std::cerr << "Heap allocation failed" << std::endl;
		CloseHandle(file);
		return 1;
	}

	// read file bytes to memory
	if (!ReadFile(file, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		std::cerr << "Failed to read file" << std::endl;
		HeapFree(GetProcessHeap(), 0, fileData);
		CloseHandle(file);
		return 1;
	}

	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;
	cout<<"******* DOS HEADER *******\n";
	cout<<"\t0x"<< dosHeader->e_magic<<"\t\tMagic number\n";
	cout<<"\t0x"<< dosHeader->e_cblp<<"\t\tBytes on last page of file\n";
	cout<<"\t0x"<< dosHeader->e_cp<<"\t\tPages in file\n";
	cout<<"\t0x"<< dosHeader->e_crlc<<"\t\tRelocations\n";
	cout<<"\t0x"<< dosHeader->e_cparhdr<<"\t\tSize of header in paragraphs\n";
	cout<<"\t0x"<< dosHeader->e_minalloc<<"\t\tMinimum extra paragraphs needed\n";
	cout<<"\t0x"<< dosHeader->e_maxalloc<<"\t\tMaximum extra paragraphs needed\n";
	cout<<"\t0x"<< dosHeader->e_ss<<"\t\tInitial(relative) SS value\n";
	cout<<"\t0x"<< dosHeader->e_sp<<"\t\tInitial SP value\n";
	cout<<"\t0x"<< dosHeader->e_sp<<"\t\tInitial SP value\n";
	cout<<"\t0x"<< dosHeader->e_csum<<"\t\tChecksum\n";
	cout<<"\t0x"<< dosHeader->e_ip<<"\t\tInitial IP value\n";
	cout<<"\t0x"<< dosHeader->e_cs<<"\t\tInitial(relative) CS value\n";
	cout<<"\t0x"<< dosHeader->e_ovno<<"\t\tOverlay number\n";
	cout<<"\t0x"<< dosHeader->e_oemid<<"\t\tOEM identifier(for e_oeminfo)\n";
	cout<<"\t0x"<< dosHeader->e_oeminfo<<"\t\tOEM information; e_oemid specific\n";
	cout<<"\t0x"<< dosHeader->e_lfanew<<"\t\tFile address of new exe header\n";

	cout<<"\t0x"<< dosHeader->e_lfarlc<<"\t\tFile address of relocation table\n";
	// IMAGE_NT_HEADERS
	IMAGE_NT_HEADERS* imageNTHeaders = (IMAGE_NT_HEADERS*)((BYTE*)fileData + dosHeader->e_lfanew);
	cout<<"\n******* NT HEADERS *******\n";
	cout<< imageNTHeaders->Signature<<"\t\t\tSignature\n";

	// FILE_HEADER
	cout<<"\n******* FILE HEADER *******\n";
	cout<<"\t0x"<< imageNTHeaders->FileHeader.Machine <<"\t\tMachine\n";
	cout<<"\t0x"<< imageNTHeaders->FileHeader.NumberOfSections <<"\t\tNumber of Sections\n";
	cout<<"\t0x"<< imageNTHeaders->FileHeader.TimeDateStamp <<"\tTime Stamp\n";
	cout<<"\t0x"<< imageNTHeaders->FileHeader.PointerToSymbolTable <<"\t\tPointer to Symbol Table\n";
	cout<<"\t0x"<< imageNTHeaders->FileHeader.NumberOfSymbols <<"\t\tNumber of Symbols\n";
	cout<<"\t0x"<< imageNTHeaders->FileHeader.SizeOfOptionalHeader <<"\t\tSize of Optional Header\n";
	cout<<"\t0x"<< imageNTHeaders->FileHeader.Characteristics <<"\t\tCharacteristics\n";

	// OPTIONAL_HEADER
	cout<<"\n******* OPTIONAL HEADER *******\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.Magic <<"\t\tMagic\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MajorLinkerVersion <<"\t\tMajor Linker Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MinorLinkerVersion <<"\t\tMinor Linker Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfCode <<"\t\tSize Of Code\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfInitializedData <<"\t\tSize Of Initialized Data\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfUninitializedData <<"\t\tSize Of UnInitialized Data\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.AddressOfEntryPoint <<"\t\tAddress Of Entry Point (.text)\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.BaseOfCode <<"\t\tBase Of Code\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.DataDirectory<<"\t\tBase Of Data\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.ImageBase <<"\t\tImage Base\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SectionAlignment <<"\t\tSection Alignment\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.FileAlignment <<"\t\tFile Alignment\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion <<"\t\tMajor Operating System Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion <<"\t\tMinor Operating System Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MajorImageVersion <<"\t\tMajor Image Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MinorImageVersion <<"\t\tMinor Image Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MajorSubsystemVersion <<"\t\tMajor Subsystem Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.MinorSubsystemVersion <<"\t\tMinor Subsystem Version\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.Win32VersionValue <<"\t\tWin32 Version Value\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfImage <<"\t\tSize Of Image\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfHeaders <<"\t\tSize Of Headers\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.CheckSum <<"\t\tCheckSum\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.Subsystem <<"\t\tSubsystem\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.DllCharacteristics <<"\t\tDllCharacteristics\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfStackReserve <<"\t\tSize Of Stack Reserve\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfStackCommit <<"\t\tSize Of Stack Commit\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfHeapReserve <<"\t\tSize Of Heap Reserve\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.SizeOfHeapCommit <<"\t\tSize Of Heap Commit\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.LoaderFlags <<"\t\tLoader Flags\n";
	cout<<"\t0x"<< imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes <<"\t\tNumber Of Rva And Sizes\n";
	cout << "\t0x" << (DWORD)(sizeof(IMAGE_FILE_HEADER)) << "\t\tbla bla bla\n";
	cout << "\t0x" << (DWORD)(sizeof(IMAGE_OPTIONAL_HEADER)) << "\t\tbla bla bla\n";
	

	// DATA_DIRECTORIES
	cout<<"\n******* DATA DIRECTORIES *******\n";
	cout<<"\tExport Directory Address: 0x"<< imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress << "\t\tSize: 0x" << imageNTHeaders->OptionalHeader.DataDirectory[0].Size << "\n";
	cout<<"\tImport Directory Address: 0x"<< imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress << "\t\tSize: 0x" << imageNTHeaders->OptionalHeader.DataDirectory[1].Size << "\n";

	// Parse Section Headers
	cout << "\n******* SECTION HEADERS *******\n";
	sectionHeader = IMAGE_FIRST_SECTION(imageNTHeaders);
	// Get file offset to import table
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD importTableRawOffset = 0;
	char* dllName = nullptr;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {

		DWORD sectionStartRVA = sectionHeader->VirtualAddress;
		DWORD sectionEndRVA = sectionStartRVA + sectionHeader->Misc.VirtualSize;

		cout << "Section Name: " << string((char*)sectionHeader->Name, 8) << endl;
		cout << "\tVirtual Size: 0x" << hex << sectionHeader->Misc.VirtualSize << endl;
		cout << "\tVirtual Address: 0x" << hex << sectionHeader->VirtualAddress << endl;
		cout << "\tSize of Raw Data: 0x" << hex << sectionHeader->SizeOfRawData << endl;
		cout << "\tPointer to Raw Data: 0x" << hex << sectionHeader->PointerToRawData << endl;
		cout << "\tCharacteristics: 0x" << hex << sectionHeader->Characteristics << endl;

		// Check if the import table RVA lies within this section
		if (importDirectoryRVA >= sectionStartRVA && importDirectoryRVA < sectionEndRVA) {
			// Calculate the file offset (raw offset) from the RVA
			importTableRawOffset = sectionHeader->PointerToRawData + (importDirectoryRVA - sectionStartRVA);
			break;
		}
	}
	
	// Get file offset to import descriptor
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)fileData + importTableRawOffset);

	if (importDescriptor == nullptr) {
		cerr << "Failed to locate the import descriptor." << endl;
		HeapFree(GetProcessHeap(), 0, fileData);
		CloseHandle(file);
		return 1;
	}
	cout << "\n******* IMPORT DESCRIPTORS TABLE *******\n";

	while (importDescriptor->Characteristics != 0) {  // Loop until the end of the descriptors (empty descriptor found)
		cout << "-------------------------------------------------------------------------------------" << endl;
		cout << "OriginalFirstThunk: 0x" << hex << importDescriptor->OriginalFirstThunk << endl;
		cout << "TimeDateStamp: 0x" << hex << importDescriptor->TimeDateStamp << endl;
		cout << "ForwarderChain: 0x" << hex << importDescriptor->ForwarderChain << endl;
		cout << "Name RVA: 0x" << hex << importDescriptor->Name << endl;
		cout << "FirstThunk: 0x" << hex << importDescriptor->FirstThunk << endl;
		cout << "-------------------------------------------------------------------------------------" << endl;

		// Move to the next import descriptor
		importDescriptor++;
	}

	// Get the Export Directory
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)fileData + exportDirectoryRVA);
	// Get the Export Directory
	// Retrieve function names and ordinals
	DWORD* addressOfFunctions = (DWORD*)((BYTE*)fileData + exportDirectory->AddressOfFunctions);
	DWORD* addressOfNames = (DWORD*)((BYTE*)fileData + exportDirectory->AddressOfNames);
	WORD* addressOfNameOrdinals = (WORD*)((BYTE*)fileData + exportDirectory->AddressOfNameOrdinals);


	return 0;
}