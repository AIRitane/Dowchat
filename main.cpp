#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <iostream>
#include "main.h"
#include <Shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

//#define DEBUG

/*DEBUG��ӡ�궨��*/
#ifdef DEBUG
#define DeBugInfo(...) printf(__VA_ARGS__)
#else
#define DeBugInfo(...) ;
#endif // DEBUG

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
 * @brief �õ�΢��PID
 * @param Pids ΢��pid����BUF
 * @return ��������
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
 * @brief ���ƾ��
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
 * @brief �ж�num��pid�Ƿ����
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
 * @brief ��ȡϵͳ�����Ϣ
 * @param pbuffer
 * @return
*/
BOOL GetSystemHandleInfo(PVOID* pbuffer)
{
	NTSTATUS Status;
	DWORD dwSize = 0;

	//��ȡϵͳ�����Ϣ
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
			// �����ҿ��Ա�֤�������ȷ��ʹ��ѭ�������Ժ�
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
 * @brief ɾ��΢�ŵ�ʵ����־
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

			// ƥ���Ƿ�Ϊ��Ҫ�رյľ������
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
				//DeBugInfo("��ɾ��΢�ŵ���־");
			}

			CloseHandle(hHandle);
		}
	}
	return TRUE;
}

/**
 * @brief ˫��΢��
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
		DeBugInfo("�Ҳ���ϵͳ�����Ϣ\n");
		goto Exit0;
	}

	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION1)pbuffer;
	//ɾ����ʵ����־
	if (!DeleteSingleWeChat(&pHandleInfo, Pids, Num))
	{
		DeBugInfo("ɾ��΢�ŵ���־ʧ��\n");
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
 * @brief ��΢��app
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
	printf("--------------- WeChat���Զ˶࿪��(��������-----------------\n");
	printf("--------------- 2023��102��12�� AIRitane -----------------------\n");
	printf("--------------- CopyRight (C) 2023 by AIRitane ---------------\n");
	printf("------------------------------------------------------------\n\n");

	PatchWeChat();
	OpenWeChat();
}