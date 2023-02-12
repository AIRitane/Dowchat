#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <iostream>
#include "main.h"
#include <Shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

//#define DEBUG

/*DEBUG打印宏定义*/
#ifdef DEBUG
#define DeBugInfo(...) printf(__VA_ARGS__)
#else
#define DeBugInfo(...) ;
#endif // DEBUG

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
				if (!_wcsicmp((const wchar_t*)Name, (const wchar_t*)pe32.szExeFile))
				{
					DeBugInfo("%ls\n", pe32.szExeFile);
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

/**
 * @brief 得到微信PID
 * @param Pids 微信pid缓存BUF
 * @return 进程数量
*/
DWORD GetWeChatPid(DWORD* Pids)
{
	DWORD Num = GetProcIds(ConvertLPSTRoLPWSTR("WeChat.exe"), Pids);
	for (size_t i = 0; i < Num; i++)
	{
		DeBugInfo("%d : %d\n", i, Pids[i]);
	}

	return Num;
}

/**
 * @brief 复制句柄
 * @param pid
 * @param h
 * @param flags
 * @return
*/
HANDLE DuplicateHandleEx(DWORD pid, HANDLE h, DWORD flags)
{
	HANDLE hHandle = NULL;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc)
	{
		if (!DuplicateHandle(hProc,
			(HANDLE)h, GetCurrentProcess(),
			&hHandle, 0, FALSE, /*DUPLICATE_SAME_ACCESS*/flags))
		{
			hHandle = NULL;
		}
		CloseHandle(hProc);
	}

	return hHandle;
}

/**
 * @brief 判断num个pid是否相等
 * @param Pid
 * @param Pids
 * @param num
 * @return
*/
BOOL IsTargetPid(DWORD Pid, DWORD* Pids, int num)
{
	for (int i = 0; i < num; i++)
	{
		if (Pid == Pids[i])
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * @brief 获取系统句柄信息
 * @param pbuffer
 * @return
*/
BOOL GetSystemHandleInfo(PVOID* pbuffer)
{
	NTSTATUS Status;
	DWORD dwSize = 0;

	//获取系统句柄信息
	*pbuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);;
	if (!*pbuffer)
	{
		return FALSE;
	}
	Status = ZwQuerySystemInformation(SystemHandleInformation, *pbuffer, 0x1000, &dwSize);
	DeBugInfo("dwSize = %d\n", dwSize);

	if (!NT_SUCCESS(Status))
	{
		if (STATUS_INFO_LENGTH_MISMATCH != Status)
		{
			return FALSE;
		}
		else
		{
			// 这里大家可以保证程序的正确性使用循环分配稍好
			if (NULL != *pbuffer)
			{
				VirtualFree(*pbuffer, 0, MEM_RELEASE);
			}

			if (dwSize * 2 > 0x4000000)  // MAXSIZE
			{
				return FALSE;
			}

			*pbuffer = VirtualAlloc(NULL, dwSize * 2, MEM_COMMIT, PAGE_READWRITE);

			if (!*pbuffer)
			{
				return FALSE;
			}

			Status = ZwQuerySystemInformation(SystemHandleInformation, *pbuffer, dwSize * 2, NULL);

			if (!NT_SUCCESS(Status))
			{
				return FALSE;
			}
		}
	}

	return TRUE;
}

/**
 * @brief 删除微信单实例标志
 * @param pHandleInfo
 * @param Pids
 * @param Num
 * @return
*/
BOOL DeleteSingleWeChat(PSYSTEM_HANDLE_INFORMATION1* pHandleInfo, DWORD* Pids, int Num)
{
	NTSTATUS Status;
	uint32_t nIndex = 0;
	char szType[128] = { 0 };
	char szName[512] = { 0 };
	DWORD dwFlags = 0;
	POBJECT_NAME_INFORMATION pNameInfo;
	POBJECT_NAME_INFORMATION pNameType;

	for (nIndex = 0; nIndex < (*pHandleInfo)->NumberOfHandles; nIndex++)
	{
		if (IsTargetPid((*pHandleInfo)->Handles[nIndex].UniqueProcessId, Pids, Num))
		{
			HANDLE hHandle = DuplicateHandleEx((*pHandleInfo)->Handles[nIndex].UniqueProcessId,
				(HANDLE)(*pHandleInfo)->Handles[nIndex].HandleValue,
				DUPLICATE_SAME_ACCESS
			);
			if (hHandle == NULL) continue;

			Status = NtQueryObject(hHandle, ObjectNameInformation, szName, 512, &dwFlags);

			if (!NT_SUCCESS(Status))
			{
				CloseHandle(hHandle);
				continue;
			}

			Status = NtQueryObject(hHandle, ObjectTypeInformation, szType, 128, &dwFlags);

			if (!NT_SUCCESS(Status))
			{
				CloseHandle(hHandle);
				continue;
			}

			pNameInfo = (POBJECT_NAME_INFORMATION)szName;
			pNameType = (POBJECT_NAME_INFORMATION)szType;

			WCHAR TypName[1024] = { 0 };
			WCHAR Name[1024] = { 0 };

			wcsncpy_s(TypName, 1024, (WCHAR*)pNameType->Name.Buffer, pNameType->Name.Length / 2);
			wcsncpy_s(Name, 1024, (WCHAR*)pNameInfo->Name.Buffer, pNameInfo->Name.Length / 2);

			// 匹配是否为需要关闭的句柄名称
			if (0 == wcscmp(TypName, L"Mutant"))
			{
				//WeChat_aj5r8jpxt_Instance_Identity_Mutex_Name
				//if (wcsstr(Name, L"_WeChat_App_Instance_Identity_Mutex_Name"))
				if (wcsstr(Name, L"_WeChat_") &&
					wcsstr(Name, L"_Instance_Identity_Mutex_Name"))
				{
					CloseHandle(hHandle);

					hHandle = DuplicateHandleEx((*pHandleInfo)->Handles[nIndex].UniqueProcessId,
						(HANDLE)(*pHandleInfo)->Handles[nIndex].HandleValue,
						DUPLICATE_CLOSE_SOURCE
					);

					if (hHandle)
					{
						printf("+ Patch wechat success!\n");
						CloseHandle(hHandle);
					}
					else
					{
						printf("- Patch error: %d\n", GetLastError());
					}

					return FALSE;
				}
			}
			else
			{
				//DeBugInfo("已删除微信单标志");
			}

			CloseHandle(hHandle);
		}
	}
	return TRUE;
}

/**
 * @brief 双开微信
 * @return
*/
int PatchWeChat()
{
	DWORD Pids[100] = { 0 };
	DWORD Num = 0;
	PVOID pbuffer = NULL;

	ElevatePrivileges();
	Num = GetWeChatPid(Pids);
	PSYSTEM_HANDLE_INFORMATION1 pHandleInfo;

	if (Num == 0)
	{
		return 0;
	}
	if (!ZwQuerySystemInformation)
	{
		goto Exit0;
	}

	if (!GetSystemHandleInfo(&pbuffer))
	{
		DeBugInfo("找不到系统句柄信息\n");
		goto Exit0;
	}

	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION1)pbuffer;
	//删除单实例标志
	if (!DeleteSingleWeChat(&pHandleInfo, Pids, Num))
	{
		DeBugInfo("删除微信单标志失败\n");
		goto Exit0;
	}

Exit0:
	if (NULL != pbuffer)
	{
		VirtualFree(pbuffer, 0, MEM_RELEASE);
	}

	return 0;
}

/**
 * @brief 打开微信app
*/
void OpenWeChat()
{
	//HKEY_CURRENT_USER\Software\Tencent\WeChat InstallPath = xx
	HKEY hKey = NULL;
	if (ERROR_SUCCESS != RegOpenKey(HKEY_CURRENT_USER, L"Software\\Tencent\\WeChat", &hKey))
	{
		return;
	}

	DWORD Type = REG_SZ;
	WCHAR Path[MAX_PATH] = { 0 };
	char EXEPath[MAX_PATH] = { 0 };
	DWORD cbData = MAX_PATH * sizeof(WCHAR);
	if (ERROR_SUCCESS != RegQueryValueEx(hKey, L"InstallPath", 0, &Type, (LPBYTE)Path, &cbData))
	{
		goto __exit;
	}

	DeBugInfo("%ls\n", Path);
	sprintf_s(EXEPath, MAX_PATH-1,"%ls\\WeChat.exe", Path);

	ShellExecute(NULL, L"open", ConvertLPSTRoLPWSTR(EXEPath), NULL, NULL, SW_SHOW);

__exit:
	if (hKey)
	{
		RegCloseKey(hKey);
	}
}

int main(int argc, char* argv[])
{
	printf("------------------------------------------------------------\n");
	printf("--------------- WeChat电脑端多开器(防撤销）-----------------\n");
	printf("--------------- 2023年102月12日 AIRitane -----------------------\n");
	printf("--------------- CopyRight (C) 2023 by AIRitane ---------------\n");
	printf("------------------------------------------------------------\n\n");

	PatchWeChat();
	OpenWeChat();
}