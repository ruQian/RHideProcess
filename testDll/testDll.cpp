// testDll.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <windows.h>

int main()
{
	HMODULE hinst = LoadLibrary(_T("..\\x64\\Debug\\AppInitHook.dll"));
	if (NULL == hinst)
	{
		//��Դ����ʧ��!
		return TRUE;
	}
	getchar();
    return 0;
}

