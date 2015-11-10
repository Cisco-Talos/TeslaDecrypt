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
 *	Last revision: 07/17/2015
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
	g_bCleanupTeslaFiles(false),
	g_bForceKey(false),
	g_pAlphaDecoder(NULL)
{
	RtlZeroMemory(g_masterKey, sizeof(g_masterKey));
	RtlZeroMemory(g_sha256mKey, sizeof(g_sha256mKey));           

	if (!pLog) {
		// Initialize an empty log 
		g_pLog = new CLog();
		g_bIsMyLog = true;
	} else {
		g_pLog = pLog;
		g_bIsMyLog = false;
	}
}

CTeslaDecrypter::~CTeslaDecrypter(void)
{
	if (g_bIsMyLog && g_pLog) {
		g_pLog->Close();
		delete g_pLog;
	}
	if (g_pAlphaDecoder) delete g_pAlphaDecoder;
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
	//DWORD paymentKeyOffset = 0x64;	// Payment key offset in the "storage.bin" file (we don't care about this)
	DWORD recKeyOffset = 0x00;		// Recovery key offset in the key file
	BYTE keyFileVersion = 0;		// The "key.dat" detected file version 
	LPBYTE lpBuff = NULL;
	BYTE masterKey[32] = {0};
	CHAR recKeyHex[0x82] = {0};	// The recovery key in hex

	hFile = CreateFile(fileName, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	dwLastErr = GetLastError();

	if (hFile == INVALID_HANDLE_VALUE) 
		return false;

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize > 0x2000) {
		return false;
	}

	// Allocate the memory for the file content
	lpBuff = (LPBYTE)new BYTE[dwFileSize];
	RtlZeroMemory(lpBuff, dwFileSize);

	// Read the entire file
	bRetVal = ReadFile(hFile, lpBuff, dwFileSize, &dwBytesIo, NULL);
	CloseHandle(hFile);			// We don't need it anymore

	// Compile the offset based on the "key.dat" file size and content:
	if (!bRetVal || dwFileSize < 0x1A0) {			// 0x1A0 is the aligned (masterKeyOffset + sizeof(SHA256))
		// Wrong file size, exit...
		if (lpBuff) delete lpBuff;
		return false;
	} 
	else if (dwFileSize <= 0x280) {
		// First version of TeslaCrypt - the master key should be always located inside this key file
		yearOffset = 0x126;
		masterKeyOffset = 0x177;
		recKeyOffset = 0;
		keyFileVersion = 1;
	}
	else if (dwFileSize == 0x290) {
		// Second version of TeslaCrypt - the master key could be stripped
		yearOffset = 0x126;
		masterKeyOffset = 0x177;
		recKeyOffset = 0x84;
		keyFileVersion = 2;
	} 
	else if (dwFileSize >= 0x2F0) {
		// Third version of TeslaCrypt - All version of AlphaCrypt
		yearOffset = 0x18A;
		masterKeyOffset = 0x1DB;
		recKeyOffset = 0x84;

		// To get if this is TeslaCrypt version 3 or AlphaCrypt EXX variant analyse offset +0x1C0
		// Latest version of AlphaCrypt indeed fill the offset +0x148 and +0x19A with random OS data
		DWORD dwToCheck = *((DWORD*)(lpBuff+ 0x1C0));
		if (dwToCheck != 0) {
			// Latest version of Alphacrypt 
			keyFileVersion = 5;
			masterKeyOffset = 0x1B1;
		} else
			// Third and last version of TeslaCrypt OR first version of AlphaCrypt
			keyFileVersion = 4;
	} 

	// Verify its content
	SYSTEMTIME * pKeyTime = (PSYSTEMTIME)&lpBuff[yearOffset];
	if (pKeyTime->wYear < 2014 || pKeyTime->wYear > 2020) {
		g_pLog->WriteLine(L"ReadKeyFile - Invalid key file format (\"%s\" file).", fileName);
		if (lpBuff) delete lpBuff;
		return false;
	}
	
	if (keyFileVersion <= 3) 
		g_pLog->WriteLine(L"ReadKeyFile - Detected a TeslaCrypt version %i key file", (LPVOID)keyFileVersion);
	else
		g_pLog->WriteLine(L"ReadKeyFile - Detected an AlphaCrypt version %i key file", (LPVOID)(keyFileVersion - 3));


	// Get the master key
	RtlCopyMemory(masterKey, lpBuff + masterKeyOffset, 32);
	// Grab the recovery key (if any)
	if (recKeyOffset) {
		bool bIsHex = false;
		LPBYTE lpRecKeyPtr = lpBuff + recKeyOffset;
		
		bIsHex = CAlphaCrypt::IsBuffAnHexString(lpRecKeyPtr, 0x80);
		
		if (!bIsHex) {
			// Need to convert from binary
			lpRecKeyPtr = (LPBYTE)CAlphaCrypt::bin2hex(lpRecKeyPtr, 0x40);
			RtlCopyMemory(recKeyHex, lpRecKeyPtr, 0x80);
			delete lpRecKeyPtr;
		} else
			RtlCopyMemory(recKeyHex, lpRecKeyPtr, 0x80);
	}

	// Analyse the master key and get if it is empty
	BYTE zeroedBuff[32] = {0};
	if (memcmp(masterKey, zeroedBuff, sizeof(DWORD)) == 0) {
		g_pLog->WriteLine(L"ReadKeyFile - Warning! The master key inside the \"%s\" file is stripped down. "
			L"Unable to import the master key.", fileName);
		if (pbMasterKeyStripped) *pbMasterKeyStripped = TRUE;
		bRetVal = FALSE;
	} else
		bRetVal = TRUE;

	// Calculate the inverse of the master key (if needed)
	if (keyFileVersion >= 5) {
		g_pLog->WriteLine(L"ReadKeyFile - Detected an AlphaCrypt v2 master key, I need to normalize it...");
		bRetVal = CAlphaCrypt::GetTheInverse(masterKey, masterKey);
		if (!bRetVal) {
			g_pLog->WriteLine(L"ReadKeyFile - The calculation of the inverse key has failed. Unable to continue.");
			if (lpBuff) delete lpBuff;
			return false;
		}
	}

	// Verify here the master key
	if (keyFileVersion >= 2) {
		if (!g_pAlphaDecoder) g_pAlphaDecoder = new CAlphaCrypt(g_pLog);
		bRetVal = g_pAlphaDecoder->VerifyAlphaMasterKey(masterKey, recKeyHex);
		if (!bRetVal) {
			g_pLog->WriteLine(L"ReadKeyFile - The master key inside \"%s\" file can't be verified. "
				L"This could lead to strange results.", fileName);
			
			if (!g_bForceKey) {
				if (pbMasterKeyStripped) *pbMasterKeyStripped = TRUE;
				if (lpBuff) delete lpBuff;
				return false;
			} else {
				cl_wprintf(YELLOW, L"Warning! ");
				wprintf(L"The master key has not been verified. Strange results could happen!\r\n");
			}
		}
	}

	bRetVal = SetMasterKey(masterKey);
	if (bRetVal && pbMasterKeyStripped) *pbMasterKeyStripped = FALSE;
	
	//Cleanup here
	if (lpBuff) delete lpBuff;

	return (bRetVal != FALSE);
}

// Get master key (if it has been set)
bool CTeslaDecrypter::IsMasterKeySet(LPBYTE * lppKey, DWORD * lpdwKeySize) {
	if (!g_bKeySet) return false;
	if (lppKey) {
		LPBYTE buff = new BYTE[sizeof(g_masterKey)];
		RtlCopyMemory(buff, g_masterKey, sizeof(g_masterKey));
		*lppKey = buff;
		if (lpdwKeySize) *lpdwKeySize = sizeof(g_masterKey);
	}
	return true;
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
	BYTE fileHdr[0x100] = {0};				// Tesla/AlphaCrypt file header
	DWORD dwHdrSize = 0;					// The encrypted file header size
	DWORD dwIvOffset = NULL,				// AES IV initialization vector offset
		dwIvSize = 0x10;					// AES IV size
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

	// Check the header
	// AlphaCrypt v2 file header:
	//	+ 0x00 - Payment key in HEX (0x40 bytes)
	//	+ 0x40 - NULL Dword (0x4 bytes)
	//	+ 0x44 - Recovery key in HEX (0x80 bytes)
	//	+ 0xC4 - NULL Dword (0x4 bytes)
	if (CAlphaCrypt::IsBuffAnHexString(fileHdr, 0x20))  {
		// AlphaCrypt v2 encrypted file
		dwOrgFileSize = *((LPDWORD)(fileHdr + 0xD8));
		dwIvOffset = 0xC8;
	} else {
		// TeslaCrypt standard file
		dwOrgFileSize = *((LPDWORD)(fileHdr+0x10));
		dwIvOffset = 0;
	}
	dwHdrSize = dwIvOffset + dwIvSize + sizeof(DWORD);

	// Verify the header
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

	// Move file pointer according to Header size
	bRetVal = SetFilePointer(hOrgFile, dwHdrSize, NULL, FILE_BEGIN);
	bRetVal = ReadFile(hOrgFile, lpFileBuff, dwFileSize - dwHdrSize, &dwNumBytesIo, NULL);
	dwLastErr = GetLastError();
	CloseHandle(hOrgFile);			// Close original file handle

	if (!bRetVal) {
		g_pLog->WriteLine(L"DecryptTeslaFile - Error, unable to read from \"%s\" file. Returned error: %i.", orgFile, (LPVOID)dwLastErr);
		if (lpFileBuff) VirtualFree(lpFileBuff, 0, MEM_RELEASE);
		return false;
	}

	// Try to perform the decryption now
	bRetVal = EncDecWithAes256(lpFileBuff, dwFileSize - dwHdrSize, fileHdr + dwIvOffset, &lpDecBuff, &dwFileSize, false);
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

	if (destFile) 
		// If I don't have to keep the original file delete it
		if (!g_bKeepOriginalFiles) {
			BOOL dRetVal = DeleteFile(orgFile);
			if (dRetVal)
				g_pLog->WriteLine(L"DecryptTeslaFile - Original encrypted file (\"%s\") deleted.", orgFile);
		} else {
			g_pLog->WriteLine(L"DecryptTeslaFile - A backup of the original encrypted file "
			L"was stored in \"%s\".", orgFile);
		}

	if (hDestFile != INVALID_HANDLE_VALUE && bRetVal) {
		g_pLog->WriteLine(L"DecryptTeslaFile - Successfully decrypted \"%s\" file.", destFile);
		return true;
	} else {		
		g_pLog->WriteLine(L"DecryptTeslaFile - Unable to write the decrypted file (\"%s\"). Returned error: %i.", destFile, (LPVOID)dwLastErr);
		return false;
	}
}

// Check if a filename matches the pattern string
bool CTeslaDecrypter::CheckFileNameInPattern(LPTSTR fileName, LPTSTR pattern) {
	LPTSTR fPattern = NULL;				// Formatted pattern string
	LPTSTR lpExtPtr = NULL;				// File extension pointer
	LPTSTR lpCurPtr = NULL,				// Current pointer in the pattern string
		lpEndPtr = NULL;				// End pointer in the pattern string
	DWORD dwFileNameLen = 0;			// File name string length
	DWORD dwPatternStrLen = 0;			// Pattern string length
	bool bExtFound = false;				// True if I have found an extension in the pattern

	if (!fileName) return false;
	if (!pattern) return true;

	dwPatternStrLen = wcslen(pattern);			// Remember the space for the NULL char
	fPattern = new TCHAR[dwPatternStrLen+6];
	RtlZeroMemory(fPattern, (dwPatternStrLen+6) * sizeof(TCHAR));
	wcscpy_s(fPattern, dwPatternStrLen+1, pattern);
	if (pattern[dwPatternStrLen-1] != L';') {
		fPattern[dwPatternStrLen++] = L';';
		fPattern[dwPatternStrLen] = 0;
	}
	
	// Get the file extension
	lpExtPtr = wcsrchr(fileName, L'.');
	if (!lpExtPtr) {
		delete fPattern;
		return false;
	} else
		lpExtPtr++;

	// Search if the file extension is inside the pattern
	lpCurPtr = fPattern;
	while ((lpEndPtr = wcschr(lpCurPtr, L';')) != NULL) {
		LPTSTR lpDotPtr = NULL;			// The dot pointer
		lpEndPtr[0] = 0;
		lpDotPtr = wcschr(lpCurPtr, L'.');
		if (lpDotPtr) lpDotPtr++;
		else lpDotPtr = lpCurPtr;

		// Here theoretically I need to implement even the body pattern match
		// But we don't care in this version of the decryptor
		// Too lazy man! :-)
		if (_wcsicmp(lpDotPtr, lpExtPtr) == 0) 
			bExtFound = true;
		else if (_wcsicmp(lpDotPtr, L"*") == 0 ||
			_wcsicmp(lpDotPtr, L"*.*") == 0)
			// Global search pattern
			bExtFound = true;

		lpEndPtr[0] = L';';
		lpCurPtr = lpEndPtr + 1;

		if (bExtFound) break;
	}
	
	// Cleanup
	delete fPattern;
	return bExtFound;
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
	wcscat_s(fullSearchPattern, COUNTOF(fullSearchPattern), L"*.*");

	// Damn heck FindFirstFile API doesn't support multiple pattern
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
		
		if (_wcsicmp(findData.cFileName, L"..") == 0 ||
			_wcsicmp(findData.cFileName, L".") == 0) 
		{
			// Wrong filename, go to next file
			bRetVal = FindNextFile(hSearch, &findData);
			continue;
		}

		if (GetFileAttributes(fileFullPath) & FILE_ATTRIBUTE_DIRECTORY) {
			// This is a directory
			if (bRecursive == true) {
				bRetVal = DecryptDirectory(fileFullPath, pattern, true, bStripExt, true);
				if (bRetVal) bAtLeastOneDecrypted = true;
			} else {
				// Go next
				bRetVal = FindNextFile(hSearch, &findData);
				continue;
			}
		} 

		// Should I have to cleanup all the TeslaCrypt files?
		bool bIsGarbageFile = 
			(_wcsicmp(findData.cFileName, L"HELP_RESTORE_FILES.txt") == 0);
		bIsGarbageFile |= 
			(_wcsicmp(findData.cFileName, L"HELP_RESTORE_FILES.bmp") == 0);
		bIsGarbageFile |= 
			(_wcsnicmp(findData.cFileName,L"HELP_RESTORE_FILES_", 19) == 0);
		bIsGarbageFile |= 
			(_wcsicmp(findData.cFileName, L"HELP_TO_SAVE_FILES.txt") == 0);
			
		if (g_bCleanupTeslaFiles && bIsGarbageFile) {
			bRetVal = DeleteFile(fileFullPath);
			if (bRetVal)
				g_pLog->WriteLine(L"DecryptDirectory - TeslaCrypt garbage file (\"%s\") deleted.", fileFullPath);
			// Continue the cycle.... uuuhm ... Maybe it's going to continue in the next block???
			bRetVal = FindNextFile(hSearch, &findData);
			continue;
		}

		// Check here if the file name has 
		if (!CheckFileNameInPattern(fileFullPath, pattern)) {
			// This file doesn't match, go next
			bRetVal = FindNextFile(hSearch, &findData);
			continue;
		}

		// Strip the ".ecc" (".ezz", ".exx" or whatever) part if it exists
		LPTSTR extPtr = wcsrchr(fileFullPath, L'.');
		if (bStripExt) {
			lpDestFileName = new TCHAR[MAX_PATH];
			wcsncpy_s(lpDestFileName, MAX_PATH, fileFullPath, extPtr - fileFullPath);
		}

		bRetVal = DecryptTeslaFile(fileFullPath, lpDestFileName);
		if (!bRetVal) bSomeErrors = true;
		else bAtLeastOneDecrypted = true;

		// Delete the new file name buffer 
		if (lpDestFileName) {
			delete lpDestFileName;
			lpDestFileName = NULL;
		}

		// Go to next file
		bRetVal = FindNextFile(hSearch, &findData);
	}
	FindClose(hSearch);

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
