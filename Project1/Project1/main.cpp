#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <winstring.h>
#include <combaseapi.h>
#include <roapi.h>

#include "TokenBrokerIntenal_h.h"

#pragma comment(lib, "WindowsApp.lib")
//
//
//
int _tmain(int argc, _TCHAR* argv[])
{
	BOOL Res = FALSE;
	HRESULT hr;

	_tprintf(_T("[*] %hs\n"), __FUNCTION__);

	//
	// https://cpp.hotexamples.com/examples/-/-/WindowsCreateStringReference/cpp-windowscreatestringreference-function-examples.html
	//
	static const WCHAR * acid = L"Windows.Internal.Security.Authentication.Web.TokenBrokerInternal";
	const UINT32 acidLen = (UINT32)wcslen(acid);

	HSTRING acidString = NULL;
	HSTRING_HEADER headerAcidString;

	hr = WindowsCreateStringReference(acid, acidLen, &headerAcidString, &acidString);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with WindowsCreateStringReference: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	CoInitialize(NULL);

	IID IID_ITokenBrokerInternalStatics;
	hr = IIDFromString(L"{07650a66-66ea-489d-aa90-0dabc75f3567}", &IID_ITokenBrokerInternalStatics);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with IIDFromString: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	ITokenBrokerInternalStatics * tokenBrokerInternalStatics;

	hr = RoGetActivationFactory(acidString, IID_ITokenBrokerInternalStatics, (void **)&tokenBrokerInternalStatics);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with RoGetActivationFactory: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	_tprintf(_T("[*] tokenBrokerInternalStatics: %p\n"), tokenBrokerInternalStatics);

	/*
	hr = CoSetProxyBlanket()
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with RoGetActivationFactory: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	*/

end:
	if (acidString != NULL)
		WindowsDeleteString(acidString);

	return (int)Res;
}


