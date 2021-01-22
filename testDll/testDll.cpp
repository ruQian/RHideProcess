// testDll.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>

int main()
{
	HMODULE hinst = LoadLibrary(_T("..\\x64\\Debug\\AppInitHook.dll"));
	if (NULL == hinst)
	{
		//资源加载失败!
		return TRUE;
	}
	getchar();
    return 0;
}

