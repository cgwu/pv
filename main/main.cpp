#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <time.h>
#include <vector>
using namespace std;


// Load structure from binary file
template<typename T>
T* LoadStructure(FILE *fp)
{
	T *pStructure = new T;
	int size = sizeof(T);
	fread(pStructure, size, 1, fp);
	return pStructure;
}
char* LoadCStr(char *buf, WORD addr, FILE *fp)
{
	long origin = ftell( fp );
	fseek(fp, addr, SEEK_SET);
	char * ret = fgets(buf,128, fp);
	fseek(fp, origin, SEEK_SET);
	return ret;
}
void Split()
{
	cout << "------------------------------------" << endl;
}

int main()
{
	FILE * fp;
	fp = fopen("E:\\temp\\notepad.exe", "r");
	if(!fp){
		cout << "Cannot open file!" << endl;
	}
    UINT uDosHeader = sizeof(IMAGE_DOS_HEADER);
	IMAGE_DOS_HEADER *pDosHeader = LoadStructure<IMAGE_DOS_HEADER>(fp);
	cout << "DOS Header: " << uDosHeader << " bytes" << endl;
	printf("Magic number: %c%c\n", LOBYTE(pDosHeader->e_magic), HIBYTE(pDosHeader->e_magic));
	printf("NT header offset: 0x%08X\n", pDosHeader->e_lfanew);
	
	Split();
	/*
	SEEK_SET  Seek from the start of the file  
	SEEK_CUR  Seek from the current location  
	SEEK_END  Seek from the end of the file 
	*/
	fseek(fp, pDosHeader->e_lfanew, SEEK_SET);
	
	UINT uNTHeader = sizeof(IMAGE_NT_HEADERS);
	IMAGE_NT_HEADERS *pNTHeader = LoadStructure<IMAGE_NT_HEADERS>(fp);
	cout << "NT Header: " << uNTHeader << " bytes" << endl;
	byte * bSig= (byte*)&pNTHeader->Signature;
	printf("Signature: %c%c%d%d 0x%08X\n", bSig[0], bSig[1], bSig[2], bSig[3], pNTHeader->Signature);

	cout << endl << "IMAGE_FILE_HEADER:"<< endl;
	if(pNTHeader->FileHeader.Machine == 0x014c) printf("Machine: Intel 386 (i386)\n");
	printf("NumberOfSections: %d\n", pNTHeader->FileHeader.NumberOfSections);
	printf("TimeDateStamp: %s", ctime((const long *)&pNTHeader->FileHeader.TimeDateStamp));
	printf("SizeOfOptionalHeader: %d\n", pNTHeader->FileHeader.SizeOfOptionalHeader);
	cout <<"Characteristics: ";
	if(pNTHeader->FileHeader.Characteristics & 0x0002) cout << "executable ";
	if(pNTHeader->FileHeader.Characteristics & 0x2000) cout << "dll ";
	cout << endl;

	cout << endl << "IMAGE_OPTIONAL_HEADER32:"<< endl;
	printf("Magic: 0x%04X\n", pNTHeader->OptionalHeader.Magic);
	printf("AddressOfEntryPoint: 0x%08X\n", pNTHeader->OptionalHeader.AddressOfEntryPoint);
	printf("ImageBase: 0x%08X\n", pNTHeader->OptionalHeader.ImageBase);
	printf("SectionAlignment: 0x%08X (Memory unit)\n", pNTHeader->OptionalHeader.SectionAlignment);
	printf("FileAlignment: 0x%08X (File unit)\n", pNTHeader->OptionalHeader.FileAlignment);
	printf("SizeOfImage: %u (bytes)\n", pNTHeader->OptionalHeader.SizeOfImage);
	printf("SizeOfHeaders: %u (bytes)\n", pNTHeader->OptionalHeader.SizeOfHeaders);
	printf("Subsystem: %u (1: Driver, 2: GUI, 3: CUI)\n", pNTHeader->OptionalHeader.Subsystem);
	printf("IMAGE_DATA_DIRECTORY DataDirectory[%d] (0:EXPORT_DIRECTORY, 1:IMPORT_DIRECTORY, "
		"\t\t2:RESOURCE_DIRECTORY, 9:TLS_DIRECTORY)\n", 
		IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

	Split();
	cout << "Section Headers:" << endl;
	printf("%-4s%-10s%-15s%-15s%-10s%-10s%-10s\n", "No.", "Name", "VirtualSize", "VirtualOffset", 
			"RawSize", "RawOffset","Characteristics");
	int iSec = 0;
	
	DWORD diffVR;	// RVA Raw offset diff
	for(;iSec < pNTHeader->FileHeader.NumberOfSections; ++iSec){
		IMAGE_SECTION_HEADER *pSecHeader = LoadStructure<IMAGE_SECTION_HEADER>(fp);
		printf("%-4d%-10s%-15X%-15X%-10X%-10X%-10X\n", iSec, pSecHeader->Name, pSecHeader->Misc.VirtualSize,
			pSecHeader->VirtualAddress, pSecHeader->SizeOfRawData, pSecHeader->PointerToRawData ,
			pSecHeader->Characteristics);
		if(iSec == 0){
			diffVR = pSecHeader->VirtualAddress - pSecHeader->PointerToRawData;
		}
		delete pSecHeader;
	}

	Split();
	// IAT(Import Address Table)
	IMAGE_DATA_DIRECTORY importDir = pNTHeader->OptionalHeader.DataDirectory[1];
	printf("IMAGE_IMPORT_DESCRIPTOR addr: 0x%08X\n", importDir.VirtualAddress);
	cout << "IMAGE_IMPORT_DESCRIPTOR total size: " << importDir.Size << endl;
	WORD rawAddr = importDir.VirtualAddress - diffVR;

	fseek(fp, rawAddr, SEEK_SET);
	char bufName[128];
	while (1)
	{
		IMAGE_IMPORT_DESCRIPTOR *pDesc = LoadStructure<IMAGE_IMPORT_DESCRIPTOR>(fp);
		if(pDesc->Name == 0 && pDesc->OriginalFirstThunk == 0) break;
		LoadCStr(bufName,pDesc->Name - diffVR, fp);
		cout << bufName;	// library name

		DWORD addrINT = pDesc->OriginalFirstThunk - diffVR;	// Point to IMAGE_IMPORT_BY_NAME Array, NULL ended.
		
		long origin = ftell( fp );		// save fp pos
		fseek(fp, addrINT, SEEK_SET);
		
		vector<DWORD> vINT;
		while (1)
		{
			DWORD tmp;
			fread(&tmp, sizeof(DWORD), 1, fp );
			if(tmp==NULL) break;
			vINT.push_back(tmp);
		}
		cout << " (used function count: " << vINT.size() <<")" << endl;
		int i = 0;
		for(;i<vINT.size(); ++i){
			fseek(fp, vINT[i] - diffVR, SEEK_SET);
			WORD ordinal;
			fread(&ordinal,sizeof WORD, 1, fp);
			fgets(bufName,128, fp);
			//printf("{Hint:%u,Name:%s}, ", ordinal, bufName);
			printf("\t%5u: %s\n", ordinal, bufName);
		}
		fseek(fp, origin, SEEK_SET);	// Restore fp pos for next IMAGE_IMPORT_DESCRIPTOR
		delete pDesc;
		printf("\n");
	}

	delete pDosHeader;
	delete pNTHeader;
	fclose(fp);
	

    //cout << "Press ENTER to exit." << endl;
	//getchar();
    return 0;
}
