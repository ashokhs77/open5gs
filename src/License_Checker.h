/****************************************************************************
 * Copyright   : All rights reserved. This document/code contains information
 * that is proprietary to Lekha Wireless Solutions Pvt. Ltd. No part of this
 * document/code may be reproduced or used in whole or part in any form or
 * by any means- graphic, electronic or mechanical without the written
 * permission of Lekha Wireless Solutions Pvt. Ltd.
 *
 * Company     : Lekha Wireless Solutions Pvt. Ltd.
 * File Name   : License_Checker.h
 * Description : License Checker API
 * Comments    : None
 *****************************************************************************/

#ifndef LICENSE_CHECKER_H_
#define LICENSE_CHECKER_H_

/* STANDARD INCLUDES ********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/* PROJECT INCLUDES *********************************************************/

/* MACRO  DEFINITIONS ***********************************************/

#if !defined _DATATYPES_H_
#define  	UINT8	unsigned char
#define		UINT16	unsigned short int
#define  	UINT32	unsigned long int
#define 	INT8	char
#define		INT16	signed short int
#define  	INT32	signed long int
#define  	FLOAT	float
#endif

#define LICENSE_VOID                 0x01
#define LICENSE_VALID                0x00


/* PRIVATE FUNCTION DEFINITIONS *********************************************/

/******************************************************************************
* Function             : checkLicense
* Description          : API to check license vailidity for given Application
* Input parameter      : si8Appname: Application name (L1_APP/L2_L3_APP)
*                        si8TOC    : Time of Compilation in following format
*                          “Week-day yyyy-mm-dd hh:mm:ss Timezone”    
* Output parameters    : i32LicenseStatus: LICENSE_VOID = License expired
*                         LICENSE_VALID = License vaild
* I/P & O/P parameter  : None
* Return value         : License Status
******************************************************************************/
INT32 checkLicense(INT8 *si8Appname, INT8 *gsi8TOC);

/******************************************************************************
 * Function             : VersionNumber
 * Description          : Return the current version number
 * Input parameter      : None
 * Output parameters    : None
 * I/P & O/P parameter  : None
 * Return value         : None
 ******************************************************************************/
void GetLicenseAPIVersionNumber(void);

#endif 
/*********************************END LICENSE_CHECKER_H_ *********************/
