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
 */

#include "stdafx.h"
#include "TeslaDecrypter.h"
#include "TeslaDecrypterApp.h"
#include <shellapi.h>


int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	LPWSTR strCompleteCmdLine = NULL;		// Complete entry point command line
	LPWSTR * argv = NULL;					// Argument array
	int argc = 0;							// Number of arguments
	
	strCompleteCmdLine = GetCommandLine();
	argv = CommandLineToArgvW(strCompleteCmdLine, &argc);

	CTeslaDecrypterApp theApp;
	return theApp.Main(argc, argv);
}

// Console application entry point
int _tmain(int argc, _TCHAR* argv[])
{	
	// pass
}
