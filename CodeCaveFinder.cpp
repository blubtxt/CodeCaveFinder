#pragma comment(lib, "psapi.lib")
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Psapi.h>

BOOL bNoProcessName = NULL;

char szProcessName[256];

DWORD dwAddress;
DWORD lpBuffer;
LPDWORD  dwBytesWritten;

HANDLE hSnapshot;
HANDLE hProcess;
HMODULE hModule;
HANDLE hToken;

PROCESSENTRY32 pe32;
MODULEENTRY32 me32;

MODULEINFO moduleInformation;

TOKEN_PRIVILEGES tpToken;

LUID luid;

int main( int argc, CHAR* argv[] )
{
	BOOL bCount         = FALSE;
	int iSize           = NULL;
	DWORD dwCaveAddress = NULL;
	BOOL bAddressSet    = FALSE;

	printf( "\n CodeCaveFinder by blub.txt \n\n" );
	printf( "\n - Usage: CodeCaveFinder.exe ProcessName \n" );
	printf( " - Example: CodeCaveFinder.exe Steam.exe \n\n" );

	if( argv[1] == NULL )
		bNoProcessName = 1;
	else
	{
		strcpy( szProcessName, argv[1] );
	}
	
	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );

	if( hSnapshot == INVALID_HANDLE_VALUE )
	{
		CloseHandle( hSnapshot );
		return 0;
	}

	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if( !Process32First( hSnapshot, &pe32 ) )
	{
		CloseHandle( hSnapshot );
		return 0;
	}

	while( Process32Next( hSnapshot, &pe32 ) )
	{
		if( bNoProcessName == 1)
			printf( "%s \n", pe32.szExeFile );

		else if( !lstrcmp( pe32.szExeFile, szProcessName ) )
		{
			printf( "Process found! %s \n", szProcessName );

			hProcess = OpenProcess( PROCESS_ALL_ACCESS, false, pe32.th32ProcessID );

			if( OpenProcessToken( hProcess, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken) == NULL )
			{
				CloseHandle( hProcess);
				return 0;
			}

			if( ( LookupPrivilegeValue( 0, SE_SECURITY_NAME, &luid ) == 0) || ( LookupPrivilegeValue( 0, SE_DEBUG_NAME, &luid ) == NULL ) )
			{
				CloseHandle( hProcess );
				return 0;	
			}

			tpToken.PrivilegeCount = 1;
			tpToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			tpToken.Privileges[0].Luid = luid;

			AdjustTokenPrivileges( hToken, false, &tpToken, sizeof( tpToken ), NULL, NULL );

			hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pe32.th32ProcessID );

			me32.dwSize = sizeof( MODULEENTRY32 );
			
			if( !Module32First( hSnapshot, &me32 ) )
			{
				CloseHandle( hProcess );
				return 0;
			}

			printf( "- Base Address: 0x%x \n", ( DWORD )me32.modBaseAddr );
			printf( "- Process Size: %x \n", me32.modBaseSize );
			
			hModule = me32.hModule;

			if( !GetModuleInformation( hProcess, hModule, &moduleInformation, sizeof( MODULEINFO ) ) )
			{
				CloseHandle( hProcess );
				return 0;
			}

			dwAddress = ( DWORD )moduleInformation.EntryPoint;

			while( ReadProcessMemory( hProcess, ( LPCVOID )dwAddress, &lpBuffer, 1, NULL ) && dwAddress <= ( DWORD ) me32.modBaseAddr + ( DWORD )me32.modBaseSize )
			{		
				if( bCount == TRUE && lpBuffer != 0x90 )
					bCount = FALSE;
		
				if ( lpBuffer == 0x90 )
					bCount = TRUE;
								
				if ( lpBuffer == 0x90 && bCount )
				{
					iSize++;
					
					if( bAddressSet == FALSE ) 
					{
						dwCaveAddress = dwAddress;
						bAddressSet = TRUE;
					}
				}

				if ( bCount == FALSE && iSize >= 2 )
				{
					printf( "NOP Address: 0x%X  Size: %i \n", dwCaveAddress, iSize );
					bAddressSet = FALSE;
					iSize = NULL;
				}
			

				if( dwAddress <= ( DWORD ) me32.modBaseAddr + ( DWORD )me32.modBaseSize )
					dwAddress = dwAddress + 0x1;
			}

			dwAddress = ( DWORD )moduleInformation.EntryPoint;

			bCount         = FALSE;
			iSize           = NULL;
			dwCaveAddress = NULL;
			bAddressSet    = FALSE;

			while( ReadProcessMemory( hProcess, ( LPCVOID )dwAddress, &lpBuffer, 1, NULL ) && dwAddress <= ( DWORD ) me32.modBaseAddr + ( DWORD )me32.modBaseSize )
			{		
				if( bCount == TRUE && lpBuffer != 0xCC )
					bCount = FALSE;

				if ( lpBuffer == 0xCC )
					bCount = TRUE;

				if ( lpBuffer == 0xCC && bCount )
				{
					iSize++;

					if( bAddressSet == FALSE ) 
					{
						dwCaveAddress = dwAddress;
						bAddressSet = TRUE;
					}
				}

				if ( bCount == FALSE && iSize >= 2 )
				{
					printf( "INT3 Address: 0x%X  Size: %i \n", dwCaveAddress, iSize );
					bAddressSet = FALSE;
					iSize = NULL;
				}


				if( dwAddress <= ( DWORD ) me32.modBaseAddr + ( DWORD )me32.modBaseSize )
					dwAddress = dwAddress + 0x1;
			}
	
		}
	}

	return 0;
}

