#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <iostream>

/**
 * @brief ������Ȩ
 * @return TRUE/FALSE
*/
BOOL ElevatePrivileges()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		return FALSE;
	}

	return TRUE;

}

/**
 * @brief LPWSTRתchar*
 * @param lpwszStrIn ��ת����LPWSTR����
 * @return ת�����char*����
*/
char* ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)
{
	LPSTR pszOut = NULL;
	try
	{
		if (lpwszStrIn != NULL)
		{
			int nInputStrLen = wcslen(lpwszStrIn);

			// Double NULL Termination  
			int nOutputStrLen = WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, NULL, 0, 0, 0) + 2;
			pszOut = new char[nOutputStrLen];

			if (pszOut)
			{
				memset(pszOut, 0x00, nOutputStrLen);
				WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, pszOut, nOutputStrLen, 0, 0);
			}
		}
	}
	catch (std::exception e)
	{
	}

	return pszOut;
}

/**
 * @brief const char*תLPWSTR
 * @param lpwszStrIn ��ת����const char*����
 * @return ת�����LPWSTR����
*/
LPWSTR ConvertLPSTRoLPWSTR(const char* str)
{
	int num = MultiByteToWideChar(0, 0, str, -1, NULL, 0);
	wchar_t* wide = new wchar_t[num];
	MultiByteToWideChar(0, 0, str, -1, wide, num);
	return wide;
}

/**
 * @brief ��ȡ����ID
 * @param Name ����ȡ������
 * @param Pids ����ID��������
 * @return ��ȡID����
*/
int GetProcIds(LPWSTR Name, DWORD* Pids)
{
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	int num = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap)
	{
		if (Process32First(hSnap, &pe32))
		{
			do {
				if (!_wcsicmp((const wchar_t*)Name, (const wchar_t *)pe32.szExeFile))
				{
					printf("%ls\n", pe32.szExeFile);
					if (Pids)
					{
						Pids[num++] = pe32.th32ProcessID;
					}
				}
			} while (Process32Next(hSnap, &pe32));
		}
		CloseHandle(hSnap);
	}

	return num;
}

void test()
{
	DWORD Pids[100] = { 0 };

	DWORD Num = GetProcIds(ConvertLPSTRoLPWSTR("WeChat.exe"), Pids);
	for (size_t i = 0; i < Num; i++)
	{
		printf("%d : %d\n",i,Pids[i]);
	}
}

int PatchWeChat()
{

	ElevatePrivileges();
	test();

	return 0;

}
int main(int argc, char* argv[])
{
	printf("------------------------------------------------------------\n");
	printf("--------------- WeChat���Զ˶࿪��(��������-----------------\n");
	printf("--------------- 2023��102��12�� AIRitane -----------------------\n");
	printf("--------------- CopyRight (C) 2023 by AIRitane ---------------\n");
	printf("------------------------------------------------------------\n\n");

	PatchWeChat();
}