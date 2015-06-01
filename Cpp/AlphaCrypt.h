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
 *	Filename: AlphaCrypt.h
 *	Class that deals with Elliptic Curve encryption of the latest 
 *	AlphaCrypt droppers definition
 *	Last revision: 06/01/2015
 */

#pragma once
#include "Log.h"

// OpenSSL include files
#include "openssl\\bn.h"
#include "openssl\\ec.h"
#include "openssl\\obj_mac.h"

class CAlphaCrypt
{
public:
	// Constructor with the associated log 
	CAlphaCrypt(CLog * pLog = NULL);
	// Default destructor
	~CAlphaCrypt();

	// Verify AlphaCrypt Master Key
	static bool VerifyAlphaMasterKey(BYTE masterKey[32], BYTE recKey[0x40]);
	static bool VerifyAlphaMasterKey(BYTE masterKey[32], LPSTR recKey);

	// Calculate the inverse of a key (needed in latest version of AlphaCrypt)
	static bool GetTheInverse(BYTE key[32], BYTE inverse[32]);

	// Binary to hex conversion
	static LPSTR bin2hex(LPBYTE buff, DWORD dwBuffLen);

	// Get if a buffer represent an Hex string
	static bool IsBuffAnHexString(LPBYTE buff, DWORD dwLen, bool bUnicode = false);

private:
	// Get the AlphaCrypt default PEER public Key
	static EC_POINT * GetAlphaCryptPublicKey();
	// Set the private key to a full-fledged curve
	static bool SetPrivateKey(EC_KEY * lpCurve, BIGNUM * lpPrivateKey);
	// Generate a Shared secret key from 
	static BIGNUM * GenerateSharedSecretKey(BIGNUM * pMasterKey, EC_POINT * lpPeerPubKey = NULL);
	// Verify the Recovery key for an AlphaCrypt infection
	static bool VerifyRecoveryKey(BIGNUM * pMasterKey, BIGNUM * pRecKey);


private:
	// The used curve ID
	static const int g_iCurveId;

	// This class instance log
	CLog * g_pLog;
	// Is this log allocated by me?
	bool g_bIsMyLog;
};
