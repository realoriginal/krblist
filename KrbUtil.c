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

/*!
 *
 * Purpose:
 *
 * Returns a string for the specified encrytion type.
 *
!*/
PCHAR KrbUtilEncryptionType( _In_ ULONG Type )
{
	switch ( Type ) 
	{
		case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
			return C_PTR( "KERB_ETYPE_AES256_CTS_HMAC_SHA1_96" );
		case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
			return C_PTR( "KERB_ETYPE_AES128_CTS_HMAC_SHA1_96" );
		case KERB_ETYPE_RC4_HMAC_NT:
			return C_PTR( "KERB_ETYPE_RC4_HMAC_NT" );
	};
	return NULL;
};
