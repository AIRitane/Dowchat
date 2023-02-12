#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <iostream>

/**
 * @brief 进程提权
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
 * @brief LPWSTR转char*
 * @param lpwszStrIn 待转化的LPWSTR类型
 * @return 转化后的char*类型
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
 * @brief const char*转LPWSTR
 * @param lpwszStrIn 待转化的const char*类型
 * @return 转化后的LPWSTR类型
*/
LPWSTR ConvertLPSTRoLPWSTR(const char* str)
{
	int num = MultiByteToWideChar(0, 0, str, -1, NULL, 0);
	wchar_t* wide = new wchar_t[num];
	MultiByteToWideChar(0, 0, str, -1, wide, num);
	return wide;
}

/**
 * @brief 获取进程ID
 * @param Name 待获取进程名
 * @param Pids 进程ID缓存数组
 * @return 获取ID个数
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
	printf("--------------- WeChat电脑端多开器(防撤销）-----------------\n");
	printf("--------------- 2023年102月12日 AIRitane -----------------------\n");
	printf("--------------- CopyRight (C) 2023 by AIRitane ---------------\n");
	printf("------------------------------------------------------------\n\n");

	PatchWeChat();
}