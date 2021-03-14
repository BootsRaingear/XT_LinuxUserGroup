///////////////////////////////////////////////////////////////////////////////
// X-Tension API - template for new X-Tensions
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "X-Tension.h"

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation
#include <windows.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <iterator>
#include <vector>
#include <locale>
#include <map>
using namespace std;

#define MIN_VER	1990
#define NAME_BUF_LEN 256
#define MSG_BUF_LEN 1024
#define VER_BUF_LEN 10

#define XWF_VSPROP_SPECIALITEMID 10;


BOOLEAN EXIT = FALSE;
HANDLE heap = NULL;
wchar_t msg[MSG_BUF_LEN];
wchar_t VER[VER_BUF_LEN];

const char* dlm = ":";
struct c_buf {
	char* ptr = 0;
	unsigned __int64 offset = 0;
	unsigned __int64 len = 0;
};

std::map<long, string> passwdMap;
std::map<long, string> groupMap;

int processCount = 0;

static wchar_t* charToWChar(const char* text)
{
	const size_t size = strlen(text) + 1;
	wchar_t* wText = new wchar_t[size];
	mbstowcs(wText, text, size);
	return wText;
}

LONG ParsePasswd(std::string p)
{
	XWF_OutputMessage(L"std::string time!", 0);
	
	XWF_OutputMessage(L"XT_LinPasswd: Parsing passwd file", 0);
	vector<string> lines;

	std::string delimeter = "\n";
	size_t pos = 0;
	std::string token;
	while ((pos = p.find(delimeter)) != std::string::npos) {
		token = p.substr(0, pos);
		lines.push_back(token);
		p.erase(0, pos + delimeter.length());
	}

	XWF_OutputMessage(L"XT_LinPasswd: Parsing passwd file", 0);

	wchar_t sz[64];
	swprintf(sz, L"%d", (int)lines.size());
	XWF_OutputMessage(sz, 0);
	
	for (int i = 0; i < lines.size(); i++) {
		if (lines[i].length() > 0)
		{
			if ((pos = lines[i].find(':')) != std::string::npos) {
				std::string nUser = lines[i].substr(0, pos);
				size_t idstart, idend;

				idstart = pos + 3;
				idend = lines[i].find(':', idstart);
				int idlen = idend - idstart;

				std::string nID_s = lines[i].substr(idstart, idlen);
				long nID = std::stol(nID_s);
				passwdMap.insert(std::pair<long, std::string>(nID, nUser));

				std::wstring wname = std::wstring(nUser.begin(), nUser.end());
				const wchar_t* wsname = wname.c_str();

				wchar_t nout[1024];
				swprintf(nout, L"%s : %d", wsname, nID);
				//XWF_OutputMessage(nout, 0);
			}

		}
	}

	return 1;
}

LONG ParseGroup(std::string g)
{
	vector<string> lines;

	std::string delimeter = "\n";
	size_t pos = 0;
	std::string token;
	while ((pos = g.find(delimeter)) != std::string::npos) {
		token = g.substr(0, pos);
		lines.push_back(token);
		g.erase(0, pos + delimeter.length());
	}

/*
	wchar_t sz[64];
	swprintf(sz, L"%d", (int)lines.size());
	XWF_OutputMessage(sz, 0);
	*/
	for (int i = 0; i < lines.size(); i++) {
		if (lines[i].length() > 0)
		{
			if ((pos = lines[i].find(':')) != std::string::npos) {
				std::string nGrp = lines[i].substr(0, pos);
				size_t idstart, idend;

				idstart = pos + 3;
				idend = lines[i].find(':', idstart);
				int idlen = idend - idstart;

				std::string nID_s = lines[i].substr(idstart, idlen);
				long nID = std::stol(nID_s);
				groupMap.insert(std::pair<long, std::string>(nID, nGrp));

				/*
				std::wstring wname = std::wstring(nGrp.begin(), nGrp.end());
				const wchar_t* wsname = wname.c_str();
				wchar_t nout[1024];
				swprintf(nout, L"%s : %l", wsname, nID);
				XWF_OutputMessage(nout, 0);
				*/
			}

		}
	}

	return 1;
}

LONG ReadPG(HANDLE hVolume)
{
	XWF_SelectVolumeSnapshot(hVolume);	
	BYTE pBufByte = 0x01;
	void* pbuffer = &pBufByte;
	LONG rootDirID = XWF_GetVSProp(10, pbuffer);	
	LONG etcID = XWF_FindItem1(rootDirID, L"etc", 0x00000001, 0);
	LONG passwdFileID = XWF_FindItem1(etcID, L"passwd", 0x00000001, 0);


	//test ofs
	/*
	VOID XWF_GetItemOfs(
		LONG nItemID,
		LPINT64 lpDefOfs,
		LPINT64 lpStartSector
	);
	*/



	//endtest ofs		

	HANDLE passwdFile = XWF_OpenItem(hVolume, passwdFileID, 0);
	if (passwdFile == 0)
	{
		XWF_OutputMessage(L"XT_LinPasswd: No passwd file found", 0);
		return 0;
	}
	const INT64 passwdFileSize = XWF_GetSize(passwdFile, NULL);

	XWF_OutputMessage(L"XT_LinPasswd: starting ReadPG", 0);

	byte* pbuf = (BYTE*)malloc(passwdFileSize * sizeof(BYTE));

	if (XWF_Read(passwdFile, 0, pbuf, passwdFileSize) == 0)
		return 0;
	const char* pchar = reinterpret_cast<const char*>(pbuf);
	std::string p = pchar;
	
	if (ParsePasswd(p) == 0)
		return 0;
	free(pbuf);

	LONG groupFileID = XWF_FindItem1(etcID, L"group", 0x00000001, 0);

	HANDLE groupFile = XWF_OpenItem(hVolume, groupFileID, 0);
	if (groupFile == 0)
	{
		XWF_OutputMessage(L"XT_LinPasswd: No group file found", 0);
		return 0;
	}
	const INT64 groupFileSize = XWF_GetSize(groupFile, NULL);
	byte* gbuf = (BYTE*)malloc(groupFileSize * sizeof(BYTE));
	if (XWF_Read(groupFile, 0, gbuf, groupFileSize) == 0)
		return 0;
	const char* gchar = reinterpret_cast<const char*>(gbuf);
	std::string g = gchar;

	if (ParseGroup(g) == 0)
		return 0;
	free(gbuf);
	return 1;
}



///////////////////////////////////////////////////////////////////////////////
// XT_Init
LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd,
   void* lpReserved)
{
   XT_RetrieveFunctionPointers();

   if (nVersion < MIN_VER) {
	   wcscpy_s(msg, L"XTV_LinuxUG: The Version of X-Ways Forensics must be v.");
	   swprintf_s(VER, L"%d", MIN_VER);
	   wcscat_s(msg, VER);
	   wcscat_s(msg, L" or Later. Exiting...");
	   XWF_OutputMessage(msg, 0);
	   EXIT = TRUE;
	   return 1;
   }

   XWF_OutputMessage (L"XT_LinPasswd initialized", 0);
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done

LONG __stdcall XT_Done(void* lpReserved)
{
   XWF_OutputMessage (L"XT_LinPasswd done", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved)
{
	XWF_OutputMessage (L"XT_LinPasswd about", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
   void* lpReserved)
{
	ReadPG(hVolume);

   //XWF_OutputMessage (L"X-Tension prepare", 0);
	return 0x01;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Finalize

LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
   void* lpReserved)
{
   //XWF_OutputMessage (L"X-Tension finalize", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItem

LONG __stdcall XT_ProcessItem(LONG nItemID, void* lpReserved)
{
    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItemEx

LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved)
{

		INT64 defOfs;
		INT64 startSector;
		XWF_GetItemOfs(nItemID, &defOfs, &startSector);
		
		wchar_t poffs[256];
		swprintf(poffs, L"%I64d", defOfs);
		//XWF_OutputMessage(poffs, 0);
		

		if (defOfs < 1)
		{
			XWF_OutputMessage(L"negative offset", 0);
			return 0;
		}

		HANDLE hVolume = (HANDLE)XWF_GetProp(hItem, 10, NULL);
		LPWSTR fname = (LPWSTR)XWF_GetProp(hItem, 9, NULL);

		if (hVolume == NULL)
		{
			XWF_OutputMessage(L"NULL volume", 0);
			return 0;
		}

		BYTE uidLBytes[2], uidUBytes[2], gidLBytes[2], gidUBytes[2];
		XWF_Read(hVolume, defOfs + 2, uidLBytes, 2);
		//XWF_Read(hVolume, defOfs + 120, uidUBytes, 16);
		XWF_Read(hVolume, defOfs + 24, gidLBytes, 2);
		//XWF_Read(hVolume, defOfs + 124, gidUBytes, 16);

		//unsigned long uid = (((unsigned long)uidUBytes[0]) << 24) | (((unsigned long)uidUBytes[1]) << 16) | (((unsigned long)uidLBytes[0]) << 8) | (((unsigned long)uidLBytes[1]));
		//unsigned long gid = (((unsigned long)gidUBytes[0]) << 24) | (((unsigned long)gidUBytes[1]) << 16) | (((unsigned long)gidLBytes[0]) << 8) | (((unsigned long)gidLBytes[1]));
		unsigned long uid = ((unsigned long)uidLBytes[1] << 8) | ((unsigned long)uidLBytes[0]);
		unsigned long gid = ((unsigned long)gidLBytes[1] << 8) | ((unsigned long)gidLBytes[0]);

		std::string uname, gname;

		auto it = passwdMap.find(uid);
		if (it != passwdMap.end())
		{
			uname = it->second;
		}
		else {
			uname = "Unknown";
		}

		it = groupMap.find(gid);
		if (it != groupMap.end())
		{
			gname = it->second;
		}
		else {
			gname = "Unknown";
		}

		std::string comment = "O: " + uname + " | G: " + gname;
		std::wstring wscomment = std::wstring(comment.begin(), comment.end());
		const wchar_t* wcomment = wscomment.c_str();

		XWF_AddComment(nItemID, const_cast<wchar_t*>(wcomment), 0x01);

   return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessSearchHit

#pragma pack(2)
struct SearchHitInfo {
   LONG iSize;
   LONG nItemID;
   LARGE_INTEGER nRelOfs;
   LARGE_INTEGER nAbsOfs;
   void* lpOptionalHitPtr;
   WORD lpSearchTermID;
   WORD nLength;
   WORD nCodePage;
   WORD nFlags;
};

LONG __stdcall XT_ProcessSearchHit(struct SearchHitInfo* info)
{
	//XWF_OutputMessage (L"X-Tension proc. sh", 0);
   return 0;
}

