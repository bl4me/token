#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <winstring.h>
#include <combaseapi.h>
#include <roapi.h>


// C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\cppwinrt\winrt
// WINRT C++ UWP app
// 
// C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\winrt\windows.foundation.h
// native C++ API
//
// C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um
// typical SDK

#include <Windows.Foundation.h>
#include <webauthenticationcoremanagerinterop.h>
#include "TokenBrokerIntenal_h.h"


//
// https://learn.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/interop-winrt-abi
// /mnt/c/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/winrt

#pragma comment(lib, "WindowsApp.lib")


#include <Windows.Foundation.h>
#include <Windows.System.Threading.h>
#include <wrl/event.h>
#include <stdio.h>
#include <Objbase.h>

using namespace ABI::Windows::Foundation;
using namespace ABI::Windows::System::Threading;
using namespace Microsoft::WRL;
using namespace Microsoft::WRL::Wrappers;



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
	ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Security::Credentials::WebAccount*>* webAccounts = NULL;

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
	__x_ABI_CSample_CITokenBrokerInternalStatics* tokenBrokerInternalStatics;

	hr = RoGetActivationFactory(acidString, IID_ITokenBrokerInternalStatics, (void **)&tokenBrokerInternalStatics);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with RoGetActivationFactory: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	_tprintf(_T("[*] tokenBrokerInternalStatics: %p\n"), tokenBrokerInternalStatics);
	
	hr = CoSetProxyBlanket(tokenBrokerInternalStatics,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IDENTIFY,
		NULL,
		EOAC_DYNAMIC_CLOAKING);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with CoSetProxyBlanket: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	
	//
	// https://learn.microsoft.com/en-us/cpp/cppcx/wrl/asyncbase-class?view=msvc-170&redirectedfrom=MSDN
	//


	
	//
	// /mnt/c/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/winrt/windows.security.authentication.web.core.h
	//
	//IAsyncOperation
	// https://learn.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/interop-winrt-cx-async
	//
	// https://learn.microsoft.com/en-us/cpp/cppcx/wrl/how-to-complete-asynchronous-operations-using-wrl?view=msvc-170
	//
	ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Security::Authentication::Web::Core::FindAllAccountsResult*>* findAllAccountsResult;

	hr = tokenBrokerInternalStatics->FindAllAccountsAsync(&findAllAccountsResult);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with FindAllAccountsAsync: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}


	ABI::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult* findAllAccountResult;
	while (TRUE)
	{
		//
		// https://devblogs.microsoft.com/oldnewthing/20230724-00/?p=108477
		
		hr = findAllAccountsResult->GetResults(&findAllAccountResult);
		if (FAILED(hr))
		{
			_ftprintf(stderr, _T("[-] %hs - Error with GetResults: 0x%x\n"), __FUNCTION__, hr);
			Res = FALSE;
			//goto end;
		}
		else
		{
			_tprintf(_T("[*] GetResults: 0x%x\n"), hr);
			break;
		}

		_tprintf(_T("[*] Sleep\n"));
		Sleep(1 * 200);
	}

	_tprintf(_T("[*] findAllAccountResult: %p\n"), findAllAccountResult);

	/*
	ABI::Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus findAllWebAccountsStatus;
	hr = findAllAccountResult->get_Status(&findAllWebAccountsStatus);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with get_Accounts: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	_tprintf(_T("[*] findAllWebAccountsStatus: 0x%x\n"), findAllWebAccountsStatus);
	
	__debugbreak();
	ABI::Windows::Security::Authentication::Web::Core::IWebProviderError * webProviderError;
	hr = findAllAccountResult->get_ProviderError(&webProviderError);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with get_ProviderError: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	_tprintf(_T("[*] webProviderError: %p\n"), webProviderError);

	UINT32 error;

	webProviderError->get_ErrorCode(&error);
	_tprintf(_T("[*] get_ErrorCode: 0x%x\n"), error);
	

	//
	// https://github.com/MisteFr/mc-w10-version-launcher/blob/c4935643dbd964bccdf1ccc91c72fc58e40b37cb/WUTokenHelper/main.cpp#L16
	//
	//__debugbreak();
	ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Security::Credentials::WebAccount*> * webAccounts;
	hr = findAllAccountResult->get_Accounts(&webAccounts);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with get_Accounts: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	*/
	webAccounts = (ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Security::Credentials::WebAccount*>*)findAllAccountResult;
	_tprintf(_T("[*] webAccounts: 0x%p\n"), webAccounts);

	UINT accountsSize;
	hr = webAccounts->get_Size(&accountsSize);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with get_Size: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	_tprintf(_T("[*] accountsSize: 0x%x\n"), accountsSize);

	
	ABI::Windows::Security::Credentials::IWebAccount * webAccount;
	UINT actual;
	hr = webAccounts->GetMany(0, 1, &webAccount, &actual);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with GetMany: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	HSTRING userName;
	hr = webAccount->get_UserName(&userName);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with get_UserName: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	PCWSTR wuserName;
	wuserName = WindowsGetStringRawBuffer(userName, NULL);
	if (wuserName != NULL)
	{
		_tprintf(_T("[*] wuserName: %ws\n"), wuserName);
	}

end:
	if (acidString != NULL)
		WindowsDeleteString(acidString);

	return (int)Res;
}


