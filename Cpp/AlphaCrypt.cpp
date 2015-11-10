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
 *	Filename: AlphaCrypt.cpp
 *	Contains the code needed to properly deal with the Elliptic 
 *	Curve encryption of the latest AlphaCrypt droppers
 *	Last revision: 01/06/2015
 */

#include "StdAfx.h"
#include "AlphaCrypt.h"

// OpenSSL EC specific files:
#include "openssl\\ecdh.h"
#include "openssl\\ec_lcl.h"
#include "openssl\\ech_locl.h"

// Set the default AlphaCrypt Curve ID (SECG curve over a 256 bit prime field)
const int CAlphaCrypt::g_iCurveId = NID_secp256k1;

// Constructor with the associated log 
CAlphaCrypt::CAlphaCrypt(CLog * pLog):
	g_pLog(NULL),
	g_bIsMyLog(false)
{
	if (!pLog) {
		// Initialize an empty log 
		g_pLog = new CLog();
		g_bIsMyLog = true;
	} else {
		g_pLog = pLog;
		g_bIsMyLog = false;
	}
}

// Default class destructor
CAlphaCrypt::~CAlphaCrypt(void)
{
	if (g_bIsMyLog && g_pLog) {
		g_pLog->Close();
		delete g_pLog;
	}
}

// Binary to hex conversion
LPSTR CAlphaCrypt::bin2hex(LPBYTE buff, DWORD dwBuffLen) {
	const LPSTR hexMap = "0123456789ABCDEF";
	DWORD strLen = dwBuffLen * 2 + 1;
	LPSTR hexBuff = new CHAR[strLen];
	RtlZeroMemory(hexBuff, strLen);

	for (int i = 0; i < (int)dwBuffLen; i ++) {
		BYTE curByte = buff[i];
		hexBuff[(i*2)] = hexMap[curByte >> 4];
		hexBuff[(i*2)+1] = hexMap[curByte & 0xF];
	}
	return hexBuff;
}

// Get if a buffer represent an Hex string
bool CAlphaCrypt::IsBuffAnHexString(LPBYTE buff, DWORD dwLen, bool bUnicode) {
	bool bIsBinary = false;	
	LPTSTR uStr = (LPTSTR)buff;
	if (!buff || dwLen < 1 || (dwLen % 2) > 0) 
		return false;

	if (!bUnicode) {
		// ASCII check
		for (int i = 0; i < (int)dwLen; i++) {
			// Verify if the key is in hex digits or in standard binary digits
			bool bIsHexDigit = 
				(buff[i] >= '0' && buff[i] <= '9') ||
				(buff[i] >= 'A' && buff[i] <= 'F');
			if (!bIsHexDigit) {
				bIsBinary = true;
				break;
			}
		}	
	} 
	else {
		// Unicode check
		if ((dwLen % 4) > 0) return false;
		for (int i = 0; i < (int)(dwLen / 2); i++) {
			// Verify if the key is in hex digits or in standard binary digits
			bool bIsHexDigit = 
				(uStr[i] >= L'0' && uStr[i] <= L'9') ||
				(uStr[i] >= L'A' && uStr[i] <= L'F');
			if (!bIsHexDigit) {
				bIsBinary = true;
				break;
			}
		}	
	}
	return (!bIsBinary);
}

// Get the AlphaCrypt default PEER public Key
EC_POINT * CAlphaCrypt::GetAlphaCryptPublicKey() {
	EC_KEY * lpPublicCurve = NULL;				// Curve that contains the public key
	EC_POINT * pubKey = NULL;					// Public key generated from the 2 coordinates
	const LPSTR XCoordHex = "46668077A4449322CA896BD64901DE333156B6FEAE75ABE5D4922A039B3CD013";
	const LPSTR YCoordHex = "304AB8B3F15F498094F14058A1D1EBE823BEF512D44210CC50BBD94128D2CD05";
	BIGNUM * pBnX = NULL, * pBnY = NULL;
	int iRet = 0;

	// Allocate the 2 points structures
	pBnX = BN_new(); pBnY = BN_new();

	// Get X and Y Coordinate
	BN_hex2bn(&pBnX, XCoordHex);
	BN_hex2bn(&pBnY, YCoordHex);

	// Create the curve that contains the public key 
	lpPublicCurve = EC_KEY_new_by_curve_name(NID_secp256k1);

	// Create the generator 
	pubKey = EC_POINT_new(lpPublicCurve->group);

	// Generate the Public key and verify it
	EC_POINT_set_affine_coordinates_GFp(lpPublicCurve->group, pubKey, pBnX, pBnY, NULL);
	EC_KEY_set_public_key(lpPublicCurve, pubKey);
	iRet = EC_KEY_check_key(lpPublicCurve);

	// Cleanup
	EC_KEY_free(lpPublicCurve);
	BN_free(pBnX); BN_free(pBnY);

	if (iRet)
		return pubKey;
	else 
		EC_POINT_free(pubKey);
	return NULL;
}

// Generate a Shared secret key from 
BIGNUM * CAlphaCrypt::GenerateSharedSecretKey(BIGNUM * pMasterKey, EC_POINT * lpPeerPubKey) {
	EC_KEY * lpFullCurve = NULL;				// Full elliptic curve
	EC_POINT * pubKey = NULL;					// The peer public key (bad guys one)
	ECDH_DATA * ecdh_data = NULL;				// Elliptic Curve data structure
	BYTE secretKey[0x20] = {0};					// Shared secret key
	BIGNUM * pSecretBn = NULL;					// Secret shared key BIGNUM
	int iRet = 0;

	if (!lpPeerPubKey)
		// Get the default AlphaCrypt peer public key
		pubKey = GetAlphaCryptPublicKey();		// DON'T forget to delete it, damn heck! :-)
	else
		// Don't delete the following one:
		pubKey = lpPeerPubKey;

	if (!pubKey) return NULL;

	// Create the FULL curve that contains public/private key pair
	lpFullCurve = EC_KEY_new_by_curve_name(NID_secp256k1);
	//EC_KEY_set_public_key(lpFullCurve, pStartKey);			// No my own public key (I need to calculate it)
	iRet = SetPrivateKey(lpFullCurve, pMasterKey);
	iRet = EC_KEY_check_key(lpFullCurve);

	// Compute the shared secret key
	ecdh_data = ecdh_check(lpFullCurve);
	if (ecdh_data)
		ecdh_data->meth = ECDH_OpenSSL();
	// Calculate shared secret key: My private Key * Peer public key
	iRet = ECDH_compute_key(secretKey, 0x20, pubKey, lpFullCurve, NULL);

	// Convert the secret key in a BIGNUMBER 
	pSecretBn = BN_bin2bn(secretKey, 0x20, NULL);

	/*////////////////////////////////////////////////////////////////////////
	//							Brief explaination:							//
		Here is what "ECDH_compute_key" does:
		Calculate "da * Qb" (that is equal to "da * db * G"). Where:
			da = my ownPrivate key (the master key)
			Qb = the peer Public key (standard one inserted in AlphaCrypt)
	*////////////////////////////////////////////////////////////////////////

	// Cleanup
	EC_KEY_free(lpFullCurve);
	if (pubKey != lpPeerPubKey)
		EC_POINT_free(pubKey);
	return pSecretBn;
}


// Verify the Recovery key for an AlphaCrypt infection
bool CAlphaCrypt::VerifyRecoveryKey(BIGNUM * pMasterKey, BIGNUM * pRecKey) {
	// secp256k1 elliptic Curve
	EC_GROUP * lpCurve = NULL;
	// Big Number Context structure
	BN_CTX * lpBnCtx = NULL;	
	// Start public key
	EC_POINT * pubMasterKey = NULL;
	BIGNUM * lpBnSecret = NULL,				// The shared secret key
		* pNewRecKey = NULL;				// New Calculated Recovery Key
	// Set if the recovery key is verified
	bool bOkRecKey = false;			
	int iRet = 0;

	// Allocate the new curve
	lpCurve = EC_GROUP_new_by_curve_name(NID_secp256k1);
	// Allocate the context for the Big Numbers operation 
	lpBnCtx = BN_CTX_new();
	pubMasterKey = EC_POINT_new(lpCurve);

	// Compute my own initial public key (Qa = da * G)
	iRet = EC_POINT_mul(lpCurve, pubMasterKey, pMasterKey, NULL, NULL, lpBnCtx);

	if (iRet) {
		lpBnSecret = GenerateSharedSecretKey(pMasterKey, NULL);

		// Generate the ReCovery Key
		pNewRecKey = BN_new();
		BN_mul(pNewRecKey, lpBnSecret, pMasterKey, lpBnCtx);
		if (BN_cmp(pNewRecKey, pRecKey) == 0)
			bOkRecKey = true;

		// Cleanup
		BN_free(pNewRecKey);
		BN_free(lpBnSecret);
	}

	// Cleanup
	EC_POINT_free(pubMasterKey);
	BN_CTX_free(lpBnCtx);
	EC_GROUP_free(lpCurve);
	return bOkRecKey;
}

// Set the private key to a full-fledged curve
bool CAlphaCrypt::SetPrivateKey(EC_KEY * lpCurve, BIGNUM * lpPrivateKey) {
	BIGNUM * lpBnCopy = NULL;
	if (!lpPrivateKey) return false;
	if (lpCurve->priv_key) {
		// Free the resource of this private key
		BN_free(lpCurve->priv_key);
	}

	// Copy the private key
	lpBnCopy = BN_new();
	if (!BN_copy(lpBnCopy, lpPrivateKey)) {
		BN_free(lpBnCopy);
		return false;
	}
	lpCurve->priv_key = lpBnCopy;
	return true;
}

// Verify AlphaCrypt Master Key
bool CAlphaCrypt::VerifyAlphaMasterKey(BYTE masterKey[32], LPSTR recKey) {
	BIGNUM * bnPrivKey = NULL,			// My private key (master key)
		* bnRecKey = NULL;				// My recovery key 
	int len = 0;						// The length of the recovery key string
	bool bRetVal = false;

	// Get the master key
	bnPrivKey = BN_bin2bn(masterKey, 0x20, NULL);
	// Get the recovery key
	len = BN_hex2bn(&bnRecKey, recKey);

	if (bnPrivKey && bnRecKey &&
		len >= 0x80)
		bRetVal = VerifyRecoveryKey(bnPrivKey, bnRecKey);

	if (bnPrivKey) BN_free(bnPrivKey);
	if (bnRecKey) BN_free(bnRecKey);
	return bRetVal;
}

bool CAlphaCrypt::VerifyAlphaMasterKey(BYTE masterKey[32], BYTE recKey[0x40]) {
	LPSTR recKeyHex = bin2hex(recKey, 0x40);
	bool bRetVal = VerifyAlphaMasterKey(masterKey, recKeyHex);
	if (recKeyHex) delete recKeyHex ;
	return bRetVal;
}

// Calculate the inverse of a key (needed in latest version of AlphaCrypt)
bool CAlphaCrypt::GetTheInverse(BYTE key[32], BYTE inverse[32]) {
	bool bRetVal = true;
	BIGNUM * lpBnKey = NULL;				// The master key
	EC_GROUP * lpCurve = NULL;				// secp256k1 elliptic Curve
	BYTE buff[0x100] = {0};					// Big buffer to prevent buffer overflow conditions
	int len = 0;
	BN_CTX * lpBnCtx = NULL;				// Big Number Context structure

	// Allocate the BIGNUMBER that host the master key, the curve and the context
	lpBnKey = BN_bin2bn(key, 0x20, NULL);
	lpCurve = EC_GROUP_new_by_curve_name(g_iCurveId);
	lpBnCtx = BN_CTX_new();

	if (!lpBnKey || !lpCurve || !lpBnCtx) {
		// Not enough available memory space - it's very unlikely that this will happen
		WriteToLog(L"CAlphaCrypt::GetTheInverse - Not enough available system resources to complete the process.");
		bRetVal = false;
	}

	// Calculate the new Master key
	if (bRetVal && BN_mod_inverse(lpBnKey, lpBnKey, &lpCurve->order, lpBnCtx) != NULL) 
		// Save the new key
		len = BN_bn2bin(lpBnKey, buff);

	if (len == 0x20) {
		RtlCopyMemory(inverse, buff, 0x20);
		bRetVal = true;
	}
	else
		bRetVal = false;

	// Free the resource needed by CONTEXT and BIGNUM structure
	if (lpBnKey) BN_free(lpBnKey);
	if (lpBnCtx) BN_CTX_free(lpBnCtx);
	if (lpCurve) EC_GROUP_free(lpCurve);

	return bRetVal;

}
