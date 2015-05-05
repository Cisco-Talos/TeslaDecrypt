/*
 *  Copyright (C) 2015 Cisco Talos Security Intelligence and Research Group
 *
 *  Authors: Andrea Allievi and Emmanuel Tacheau
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 * 
 *	Filename: TeslaDecrypter.cpp
 *	Implements the CTeslaDecrypter class, contains code needed to decrypt
 *	all the TeslaCrypt encrypted files
 *	Last revision: 04/17/2015
 *
 */

#include "StdAfx.h"
#include "TeslaDecrypter.h"
#include <openssl\sha.h>
#include <openssl\aes.h>
//#include <openssl\rand.h>
#include <crtdbg.h>

CTeslaDecrypter::CTeslaDecrypter(CLog * pLog):
	g_pLog(pLog),
	g_bKeySet(false),
	g_bIsMyLog(false),
	g_bKeepOriginalFiles(false),
	g_bCleanupTeslaFiles(false)
{
	RtlZeroMemory(g_masterKey, sizeof(g_masterKey));
	RtlZeroMemory(g_sha256mKey, sizeof(g_sha256mKey));           

	if (!pLog) {
		// Initialize an empty log 
		g_pLog = new CLog();
		g_bIsMyLog = true;
	}
}

CTeslaDecrypter::~CTeslaDecrypter(void)
{
	if (g_bIsMyLog && g_pLog) {
		g_pLog->Close();
		delete g_pLog;
	}
}

// Read the "key.dat" file and obtain the Master Key
bool CTeslaDecrypter::ReadKeyFile(LPTSTR fileName, BOOLEAN * pbMasterKeyStripped) {
	BOOL bRetVal = FALSE;
	HANDLE hFile = NULL;
	DWORD dwLastErr = 0;			// Last Win32 error
	DWORD dwFileSize = 0;			// Key file size
	DWORD dwBytesIo = 0;			// Number of bytes read
	DWORD masterKeyOffset = 0x177;	// Master key Offset in the key.dat file
	DWORD yearOffset = 0x126;		// Year WORD offset in the key.dat file
	LPBYTE lpBuff = NULL;
	BYTE masterKey[32] = {0};
	BYTE sha256[32] = {0};

	hFile = CreateFile(fileName, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	dwLastErr = GetLastError();

	if (hFile == INVALID_HANDLE_VALUE) 
		return false;

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize > 0x2000) {
		return false;
	}

	// Compile the offset based on the "key.dat" file size:
	if (dwFileSize == 0x290) {
		yearOffset = 0x126;
		masterKeyOffset = 0x177;
	} else if (dwFileSize >= 0x2F0) {
		// Last TeslaCrypt dropper (04/20/2015) ... the time is coming ...
		yearOffset = 0x18A;
		masterKeyOffset = 0x1DB;
	} else if (dwFileSize < 0x1A0) {		// 0x1A0 is the aliogned (masterKeyOffset + sizeof(SHA256))
		// Wrong file size, exit...
		return false;
	}

	// Allocate the memory for the file content
	lpBuff = (LPBYTE)new BYTE[dwFileSize];
	RtlZeroMemory(lpBuff, dwFileSize);

	// Read the entire file
	bRetVal = ReadFile(hFile, lpBuff, dwFileSize, &dwBytesIo, NULL);
	CloseHandle(hFile);			// We don't need it anymore

	// Verify its content
	SYSTEMTIME * pKeyTime = (PSYSTEMTIME)&lpBuff[yearOffset];
	if (pKeyTime->wYear < 2014 || pKeyTime->wYear > 2016) {
		g_pLog->WriteLine(L"ReadKeyFile - Invalid key file format (\"%s\" file).", fileName);
		if (lpBuff) delete lpBuff;
		return false;
	}

	// Get the master key
	RtlCopyMemory(masterKey, lpBuff + masterKeyOffset, 32);

	// Calculate the SHA256 of the key
	bRetVal = GetSha256(masterKey, sizeof(masterKey), sha256);
	if (!bRetVal)
		g_pLog->WriteLine(L"ReadKeyFile - Error! Unable to calculate the SHA256 of the master key!");

	// Analyse it and get if it is empty
	BYTE zeroedBuff[16] = {0};
	if (memcmp(masterKey, zeroedBuff, sizeof(DWORD)) == 0) {
		g_pLog->WriteLine(L"ReadKeyFile - Warning! The master key inside the \"%s\" file is stripped down. "
			L"Unable to import the master key.", fileName);
		if (pbMasterKeyStripped) *pbMasterKeyStripped = TRUE;
		bRetVal = FALSE;
	} else
		bRetVal = TRUE;

	if (bRetVal) {
		// Copy the output SHA256 and the key
		RtlCopyMemory(g_sha256mKey, sha256, sizeof(g_sha256mKey));
		RtlCopyMemory(g_masterKey, masterKey, sizeof(g_masterKey));
		LPTSTR hexKey = BytesToHex(g_masterKey, sizeof(g_masterKey), NULL);
		g_pLog->WriteLine(L"Successfully imported the master key \"%s\" from \"%s\" file.", hexKey, fileName);
		if (pbMasterKeyStripped) *pbMasterKeyStripped = FALSE;
		delete hexKey;
		g_bKeySet = true;
	} 	
	
	//Cleanup here
	if (lpBuff) delete lpBuff;

	return (bRetVal != FALSE);
}

// Manually set the master key
bool CTeslaDecrypter::SetMasterKey(BYTE key[32]) {
	BYTE sha256[32] = {0};
	bool bRetVal = false;

	// Calculate the SHA256 of the key
	bRetVal = GetSha256(key, 32, sha256);			// BANG! Don't use COUNTOF(key) when an array is passed as argument
	if (bRetVal) {
		// Copy the output SHA256 and the key
		RtlCopyMemory(g_sha256mKey, sha256, sizeof(g_sha256mKey));
		RtlCopyMemory(g_masterKey, key, sizeof(g_masterKey));
		LPTSTR hexKey = BytesToHex(g_masterKey, sizeof(g_masterKey), NULL);
		g_pLog->WriteLine(L"SetMasterKey - Successfully imported the master key \"%s\".", hexKey);
		delete hexKey;
		g_bKeySet = true;
	} else 
		g_pLog->WriteLine(L"SetMasterKey - Error! Unable to calculate the SHA256 of the master key!");

	return bRetVal;
}


// Decrypt a TeslaLocker encryped file
bool CTeslaDecrypter::DecryptTeslaFile(LPTSTR orgFile, LPTSTR destFile) {
	HANDLE hOrgFile = NULL,					// Handle to the original file ...
		hDestFile = NULL;					// ... and the handle of the target decrypted file
	BOOL bRetVal = FALSE;					// Win32 returned value
	DWORD dwNumBytesIo = 0;					// Number of bytes I/O
	DWORD dwFileSize = 0,					// Encrypted file size
		  dwOrgFileSize = 0,				// Original file size
		  dwLastErr = 0;					// Last Win32 Error
	BYTE fileHdr[0x14] = {0};				// TeslaCrypt file header
	LPBYTE lpFileBuff = NULL,				// Entire file buffer
		lpDecBuff = NULL;					// The decrypted file buffer

	// Exit if the master key is not set
	if (!g_bKeySet) return false;

	// Open the original file for read
	hOrgFile = CreateFile(orgFile, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	dwLastErr = GetLastError();

	if (hOrgFile == INVALID_HANDLE_VALUE) {
		g_pLog->WriteLine(L"DecryptTeslaFile - Unable to open \"%s\" encrypted file for reading. Last Win32 error: %i.", orgFile, (LPVOID)dwLastErr);
		return false;
	}

	// Read the file header
	bRetVal = ReadFile(hOrgFile, (LPVOID)fileHdr, sizeof(fileHdr), &dwNumBytesIo, NULL);
	dwLastErr = GetLastError();
	dwFileSize = GetFileSize(hOrgFile, NULL);

	// Verify the header
	dwOrgFileSize = *((LPDWORD)(fileHdr+0x10));
	if (!bRetVal || dwOrgFileSize > dwFileSize) {
		g_pLog->WriteLine(L"DecryptTeslaFile - The \"%s\" encrypted file format is invalid. Maybe it is already decrypted or it's not a TeslaCrypt encrypted file. (last Win32 error: %i).", orgFile, (LPVOID)dwLastErr);
		CloseHandle(hOrgFile);
		return false;
	}

	// Allocate the memory and read the entire file
	lpFileBuff = (LPBYTE)VirtualAlloc(NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
	if (!lpFileBuff) {			// I am too lazy ... :-( ... but check the returned buffer 
		g_pLog->WriteLine(L"DecryptTeslaFile - Unable to open \"%s\" encrypted file for reading. The system has not enough free resources.", orgFile);
		CloseHandle(hOrgFile);
		return false;
	}

	bRetVal = ReadFile(hOrgFile, lpFileBuff, dwFileSize - sizeof(fileHdr), &dwNumBytesIo, NULL);
	dwLastErr = GetLastError();
	CloseHandle(hOrgFile);			// Close original file handle

	if (!bRetVal) {
		g_pLog->WriteLine(L"DecryptTeslaFile - Error, unable to read from \"%s\" file. Returned error: %i.", orgFile, (LPVOID)dwLastErr);
		if (lpFileBuff) VirtualFree(lpFileBuff, 0, MEM_RELEASE);
		return false;
	}

	// Try to perform the decryption now
	bRetVal = EncDecWithAes256(lpFileBuff, dwFileSize - sizeof(fileHdr), fileHdr, &lpDecBuff, &dwFileSize, false);
	_ASSERT(dwFileSize >= dwOrgFileSize);

	// Cleanup original buffer
	if (lpFileBuff) VirtualFree(lpFileBuff, 0, MEM_RELEASE);
	lpFileBuff = NULL;

	if (!bRetVal || !lpDecBuff || !dwFileSize) {
		g_pLog->WriteLine(L"DecryptTeslaFile - Error, unable to decrypt \"%s\" file.", orgFile);
		return false;
	}

	// If I am here it means that all went well
	if (!destFile) {
		// Delete original file, Indeed we don't need it anymore
		DeleteFile(orgFile);
		destFile = orgFile;
	}

	// Open the target decrypted filename for writing
	hDestFile = CreateFile(destFile, FILE_GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	bRetVal = WriteFile(hDestFile, lpDecBuff, dwOrgFileSize, &dwNumBytesIo, NULL);
	dwLastErr = GetLastError();

	// Cleanup here:
	if (hDestFile != INVALID_HANDLE_VALUE) 
		CloseHandle(hDestFile);
	if (lpDecBuff)
		VirtualFree(lpDecBuff, 0, MEM_RELEASE);
	lpDecBuff = NULL;

	if (!g_bKeepOriginalFiles && destFile) 
		// If I don't have to keep the original file delete it
		DeleteFile(orgFile);

	if (hDestFile != INVALID_HANDLE_VALUE && bRetVal) {
		g_pLog->WriteLine(L"DecryptTeslaFile - Successfully decrypted \"%s\" file.", destFile);
		return true;
	} else {		
		g_pLog->WriteLine(L"DecryptTeslaFile - Unable to write the decrypted file (\"%s\"). Returned error: %i.", destFile, (LPVOID)dwLastErr);
		return false;
	}
}

// Decrypt an entire directory, looking for a specific pattern
bool CTeslaDecrypter::DecryptDirectory(LPTSTR dirName, LPTSTR pattern, bool bRecursive, bool bStripExt, bool bIsRecursiveCall) {
	HANDLE hSearch = NULL;					// Handle to the file search
	BOOL bRetVal = FALSE;					// Win32 returned value
	bool bSomeErrors = false,				// True if I have encountered some errors
		bAtLeastOneDecrypted = false;		// True if I have decrypted almost one file
	WIN32_FIND_DATA findData = {0};			// Win32 find data
	TCHAR fullSearchPattern[0x200] = {0};	// FULL search pattern
	DWORD dwStrLen = 0;						// String size in TCHARs
	
	// Exit if the master key is not set
	if (!g_bKeySet) return false;
	if (!FileExists(dirName)) return false;

	if (!bIsRecursiveCall)
		g_pLog->WriteLine(L"DecryptDirectory - Processing \"%s\"  directory (Recursive: %s, Strip file extensions: %s)...", dirName,
			(bRecursive ? L"True": L"False"), (bStripExt ? L"True": L"False"));

	// Create full search path
	wcscpy_s(fullSearchPattern, COUNTOF(fullSearchPattern), dirName);
	dwStrLen = wcslen(dirName);
	if (fullSearchPattern[dwStrLen-1] != '\\')  {
		wcscat_s(fullSearchPattern, COUNTOF(fullSearchPattern), L"\\");
		dwStrLen = wcslen(fullSearchPattern);
	}
	// Compose the FULL search path
	wcscat_s(fullSearchPattern, COUNTOF(fullSearchPattern), pattern);

	hSearch = FindFirstFile(fullSearchPattern, &findData);
	bRetVal = (hSearch != INVALID_HANDLE_VALUE);
	// Trim down the original search pattern
	fullSearchPattern[dwStrLen] = 0;

	while (bRetVal) {
		// Compose the full file path
		TCHAR fileFullPath[MAX_PATH] = {0};				// Full original file path
		LPTSTR lpDestFileName = NULL;					// New file full path (if needed)
		wcscpy_s(fileFullPath, COUNTOF(fileFullPath), fullSearchPattern);
		wcscat_s(fileFullPath, COUNTOF(fileFullPath), findData.cFileName);

		// Strip the ".ecc" part if it exists
		LPTSTR extPtr = wcsrchr(fileFullPath, L'.');
		if (_wcsicmp(extPtr, L".ecc") == 0 && bStripExt) {
			lpDestFileName = new TCHAR[MAX_PATH];
			wcsncpy_s(lpDestFileName, MAX_PATH, fileFullPath, extPtr - fileFullPath);
		}

		bRetVal = DecryptTeslaFile(fileFullPath, lpDestFileName);
		if (!bRetVal) bSomeErrors = true;
		else bAtLeastOneDecrypted = true;

		// Delete the new file name buffer and the original one (if needed)
		if (lpDestFileName) {
			if (!g_bKeepOriginalFiles) {
				bRetVal = DeleteFile(fileFullPath);
				if (bRetVal)
					g_pLog->WriteLine(L"DecryptDirectory - Original encrypted file (\"%s\") deleted.",
						fileFullPath);
			} else
				g_pLog->WriteLine(L"DecryptDirectory - A backup of the original encrypted file "
					L"was stored in \"%s\".", fileFullPath);
			delete lpDestFileName;
			lpDestFileName = NULL;
		}

		// Go to next file
		bRetVal = FindNextFile(hSearch, &findData);
	}
	FindClose(hSearch);

	// Now if I am in the recursive modality, examine all the directories
	if (bRecursive) {
		wcscat_s(fullSearchPattern, COUNTOF(fullSearchPattern), L"*.*");
		hSearch = FindFirstFile(fullSearchPattern, &findData);
		bRetVal = (hSearch != INVALID_HANDLE_VALUE);

		while (bRetVal) {
			if (_wcsicmp(findData.cFileName, L"..") == 0 ||
				_wcsicmp(findData.cFileName, L".") == 0) {
				// Skip this
				bRetVal = FindNextFile(hSearch, &findData);
				continue;
			}
			fullSearchPattern[dwStrLen] = 0;
			wcscat_s(fullSearchPattern, COUNTOF(fullSearchPattern), findData.cFileName);
			if (GetFileAttributes(fullSearchPattern) & FILE_ATTRIBUTE_DIRECTORY) {
				bRetVal = DecryptDirectory(fullSearchPattern, pattern, true, bStripExt, true);
				if (bRetVal) bAtLeastOneDecrypted = true;
			} else {
				// Should I have to cleanup all the TeslaCrypt files?
				bool bIsGarbageFile = 
					(_wcsicmp(findData.cFileName, L"HELP_RESTORE_FILES.txt") == 0);
				bIsGarbageFile |= 
					(_wcsicmp(findData.cFileName, L"HELP_RESTORE_FILES.bmp") == 0);
					
				if (g_bCleanupTeslaFiles && bIsGarbageFile) {
					bRetVal = DeleteFile(fullSearchPattern);
					if (bRetVal)
						g_pLog->WriteLine(L"DecryptDirectory - TeslaCrypt garbage file (\"%s\") deleted.", fullSearchPattern);
				}

			}

			// Go to next file
			bRetVal = FindNextFile(hSearch, &findData);
		}
	}

	if (bAtLeastOneDecrypted) return true;
	if (!bSomeErrors) {
		//g_pLog->WriteLine(L"DecryptDirectory - Nothing to decrypt here (\"%s\").", dirName);
		return true;
	}
	return false;
}

// Decrypt the entire Workstation
bool CTeslaDecrypter::DecryptAllPcFiles(LPTSTR pattern) {
	bool bAtLeastOneDriveOk = false,
		bSomeErrors = false;
	BOOL bRetVal = FALSE;

	DWORD drivesMask = GetLogicalDrives();

	for (int i = 0; i < sizeof(DWORD)*8; i++) {
		if ((drivesMask & (1 << i)) == 0) continue;

		TCHAR drvName[10] = {0};
		wcscpy_s(drvName, COUNTOF(drvName), L"A:\\"); 
		drvName[0] = L'A' + (TCHAR)i;

		UINT drvType = GetDriveType(drvName);
		if (drvType == DRIVE_FIXED || drvType == DRIVE_REMOTE || 
			drvType == DRIVE_REMOVABLE) {
				TCHAR fsName[0x20] = {0};			// File System name (NTFS)
				TCHAR volumeName[0x100] = {0};		// Volume name
				DWORD volSn = 0,					// Volume serial number
					fsFlags = 0,					// File system flags	
					maxPathLen = 0;					// Maximum sizes of the FS paths

				bRetVal = GetVolumeInformation(drvName, volumeName, COUNTOF(volumeName), &volSn, &maxPathLen,
					&fsFlags, fsName, COUNTOF(fsName));

				if (bRetVal) {
					// Do the decryption of this volume
					wprintf(L"Working on \"%s\" drive... ", drvName);
					bRetVal = DecryptDirectory(drvName, pattern, true);
					if (bRetVal) {
						cl_wprintf(GREEN, L"Success!\r\n");
						bAtLeastOneDriveOk = true;
					} else {
						cl_wprintf(RED, L"Some Errors!\r\n");
						bSomeErrors = true;
					}
				}
		}
		// Go to next drive
	}
	return (bAtLeastOneDriveOk || !bSomeErrors);
}

#pragma region AES-SHA256 functions
// Decrypt / encrypt with and AES CBC 256 algorithm
bool CTeslaDecrypter::EncDecWithAes256(LPBYTE lpBuff, DWORD dwBuffSize, BYTE iv[16], LPBYTE * lppOut, LPDWORD lpdwOutBuffSize, bool bEncrypt) {
	BYTE aes_key[32] = {0};				// AES 256 Master key
	const int key_length = 256;			// AES key size in bit
	LPBYTE lpOutBuff = NULL;			// Output buffer
	DWORD dwOutBuffSize = NULL;			// Output buffer aligned size
	BOOL bRetVal = FALSE;				// Returned value

	// Calculate the right output buffer size
	dwOutBuffSize = (dwBuffSize % AES_BLOCK_SIZE) + dwBuffSize;

	// Copy the current master key
	RtlCopyMemory(aes_key, g_sha256mKey, 0x20);

	// Allocate the output buffer
	lpOutBuff = (LPBYTE)VirtualAlloc(NULL, dwOutBuffSize, MEM_COMMIT, PAGE_READWRITE);
	if (!lpOutBuff) return false;
	
	// so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
	if (bEncrypt) {
		// Do the encryption
		AES_KEY enc_key = {0};			// Encryption key
		bRetVal = (AES_set_encrypt_key(aes_key, key_length, &enc_key) == 0);
		AES_cbc_encrypt(lpBuff, lpOutBuff, dwOutBuffSize, &enc_key, (LPBYTE)iv, AES_ENCRYPT);
	} else {
		// Do the decryption
		AES_KEY dec_key = {0};				// Decryption key
	    bRetVal = (AES_set_decrypt_key(aes_key, key_length, &dec_key) == 0);
		AES_cbc_encrypt(lpBuff, lpOutBuff, dwOutBuffSize, &dec_key, (LPBYTE)iv, AES_DECRYPT);
	}
	
	if (bRetVal) {
		if (lppOut) *lppOut = lpOutBuff;
		else VirtualFree(lpOutBuff, 0, MEM_RELEASE);
		if (lpdwOutBuffSize) *lpdwOutBuffSize = dwOutBuffSize;
		return true;
	}
	VirtualFree(lpOutBuff, 0, MEM_RELEASE);
	return false;
}


// Calculate the SHA256 of a target buffer
bool CTeslaDecrypter::GetSha256(LPBYTE lpBuff, DWORD dwSize, BYTE sha256[SHA256_DIGEST_LENGTH]) {
    BOOL bRetVal = FALSE;
	unsigned char hash[SHA256_DIGEST_LENGTH];
    
	SHA256_CTX sha256ctx;
    bRetVal = SHA256_Init(&sha256ctx);
    bRetVal = SHA256_Update(&sha256ctx, lpBuff, (size_t)dwSize);
	if (bRetVal) {
		bRetVal = SHA256_Final(hash, &sha256ctx);
		RtlCopyMemory(sha256, hash, SHA256_DIGEST_LENGTH);
	}

	return bRetVal != FALSE;
}

// Transform a buffer in printable hex bytes
LPTSTR CTeslaDecrypter::BytesToHex(LPBYTE buff, DWORD buffSize, TCHAR delimChr) {
	LPTSTR outStr = NULL;							// Output string (allocated from the heap)
	DWORD strSize = buffSize * 2 + 4;				// Output string size in TCHARs
	DWORD curOffset = 0;							// Current output offset
	const LPTSTR hexMap = L"0123456789ABCDEF";		// Hex map

	if (delimChr) 
		strSize += buffSize;
	
	outStr = new TCHAR[strSize];
	RtlZeroMemory(outStr, strSize * sizeof(TCHAR));
	for (unsigned i = 0; i < buffSize; i++) {
		BYTE curByte = buff[i];
		TCHAR firstHex = hexMap[(curByte >> 4)];
		TCHAR secondHex = hexMap[curByte & 0xF];
		outStr[curOffset++] = firstHex;
		outStr[curOffset++] = secondHex;
		if (delimChr)
			outStr[curOffset++] = delimChr;
	}
	if (delimChr) outStr[--curOffset] = 0;

	// IMPORTANT! Remember to delete the output string after its usage
	return outStr;
}

// Transform a printable hex bytes in a real byte stream
LPBYTE CTeslaDecrypter::HexToBytes(LPTSTR hexString, DWORD strSize) {
	LPBYTE hexBuff = NULL;				// Hex buffer
	BYTE curByte = 0;					// Current processing byte
	DWORD dwCounter = 0;				// Counter for the Hex buffer

	if (strSize % 2) strSize++;
	hexBuff = new BYTE[strSize/2];
	if (!hexBuff) return NULL;
	RtlZeroMemory(hexBuff, strSize/2);
	
	for (unsigned i = 0; i < strSize; i++) {
		TCHAR curChr = hexString[i];

		if (!(curChr >= L'0' && curChr <= L'9'))  {
			curChr &= (~0x20);
			if (curChr < L'A' || curChr > L'F') {
				delete hexBuff; return NULL;
			}
		}

		if (curChr >= L'0' && curChr <= L'9') curChr = curChr - L'0';
		else curChr = (curChr - L'A') + 10;

		if ((i % 2) == 0) curByte = ((BYTE)curChr << 4);
		else {
			curByte |= (BYTE)curChr;
			hexBuff[dwCounter++] = curByte;
			curByte = 0;
		}
	}

	return hexBuff;
}

#pragma endregion


// .... and then.. What else? ....
// An italian Lucano maybe??? Ahahahah :-)
//