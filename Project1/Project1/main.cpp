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

	//
	//
	//
	
	hr = WindowsCreateStringReference(L"Windows.Security.Authentication.Web.Core.WebTokenRequest", wcslen(L"Windows.Security.Authentication.Web.Core.WebTokenRequest"), &headerAcidString, &acidString);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with WindowsCreateStringReference: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	

	
	IID IID_IWebTokenRequestFactory;
	hr = IIDFromString(L"{6cf2141c-0ff0-4c67-b84f-99ddbe4a72c9}", &IID_IWebTokenRequestFactory);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with IIDFromString: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}
	ABI::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory * webTokenRequestFactory;

	hr = RoGetActivationFactory(acidString, IID_IWebTokenRequestFactory, (void**)&webTokenRequestFactory);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with RoGetActivationFactory: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	ABI::Windows::Security::Credentials::IWebAccountProvider * webAccountProvider;
	webAccount->get_WebAccountProvider(&webAccountProvider);

	
	hr = WindowsCreateStringReference(L"https://officeapps.live.com", wcslen(L"https://officeapps.live.com"), &headerAcidString, &acidString);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with WindowsCreateStringReference: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	ABI::Windows::Security::Authentication::Web::Core::IWebTokenRequest* webTokenRequest;
	hr = webTokenRequestFactory->CreateWithScope(webAccountProvider, acidString, &webTokenRequest);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with WindowsCreateStringReference: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	ABI::Windows::Foundation::IAsyncOperation < ABI::Windows::Security::Authentication::Web::Core::WebTokenRequestResult *>* webTokenRequestResultAsync;
	//__debugbreak();
	hr = tokenBrokerInternalStatics->RequestTokenAsync(webTokenRequest, webAccounts, 0xaabbccdd, &webTokenRequestResultAsync);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with RequestTokenAsync: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	ABI::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult * webTokenRequestResult;
	while (TRUE)
	{
		//
		// https://devblogs.microsoft.com/oldnewthing/20230724-00/?p=108477

		hr = webTokenRequestResultAsync->GetResults(&webTokenRequestResult);
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
		Sleep(1 * 2000);
	}

	_tprintf(_T("[*] webTokenRequestResult: %p\n"), webTokenRequestResult);


	ABI::Windows::Security::Authentication::Web::Core::WebTokenRequestStatus webTokenRequestStatus;
	hr = webTokenRequestResult->get_ResponseStatus(&webTokenRequestStatus);
	if (FAILED(hr))
	{
		_ftprintf(stderr, _T("[-] %hs - Error with get_ResponseStatus: 0x%x\n"), __FUNCTION__, hr);
		Res = FALSE;
		goto end;
	}

	_tprintf(_T("[*] webTokenRequestStatus: 0x%x\n"), webTokenRequestStatus);

	/*
	C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s TokenBroker
	C:\Windows\System32\OneCoreCommonProxyStub.dll
	C:\Windows\System32\windows.internal.shellcommon.TokenBrokerModal.dll
	C:\Windows\System32\Windows.Security.Authentication.Web.Core.dll

Breakpoint 0 hit
tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerInternalFactory::RequestTokenAsync:
00007ffe`8ef5ba20 4053            push    rbx
0:006> kb
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`b500b4b3     : 00000226`e5650a58 00000226`e56cc9b0 00000226`e5fad5c0 00000000`00000001 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerInternalFactory::RequestTokenAsync
01 00007ffe`b506e77b     : 00000037`32c7e098 00007ffe`971505f8 00000000`0000000e 00007ffe`971576f0 : RPCRT4!Invoke+0x73
02 00007ffe`b4fad479     : 00000226`e5678900 00000226`e5fad340 00000037`32c7e370 00007ffe`b53c7e4b : RPCRT4!Ndr64StubWorker+0xb0b
03 00007ffe`b53c5f1c     : 00000000`00000000 00000037`32c7e500 00007ffe`971576f0 00000226`e5642450 : RPCRT4!NdrStubCall3+0xc9
04 00007ffe`b4fea74b     : 00000000`00000001 00000226`e5651980 00000226`e5f0e301 0000ae34`300d1812 : combase!CStdStubBuffer_Invoke+0x7c [onecore\com\combase\ndr\ndrole\stub.cxx @ 1446]
05 00007ffe`b539bad3     : 00000226`e5651980 00000226`e667d540 0000ae34`300d19a2 00000000`00000000 : RPCRT4!CStdStubBuffer_Invoke+0x3b
06 (Inline Function)     : --------`-------- --------`-------- --------`-------- --------`-------- : combase!InvokeStubWithExceptionPolicyAndTracing::__l6::<lambda_c9f3956a20c9da92a64affc24fdd69ec>::operator()+0x18 [onecore\com\combase\dcomrem\channelb.cxx @ 1279]
07 00007ffe`b539b85e     : 00000000`00000100 00000037`32c7e4a0 00000037`32c7e448 00000226`e5678900 : combase!ObjectMethodExceptionHandlingAction<<lambda_c9f3956a20c9da92a64affc24fdd69ec> >+0x43 [onecore\com\combase\dcomrem\excepn.hxx @ 87]
08 (Inline Function)     : --------`-------- --------`-------- --------`-------- --------`-------- : combase!InvokeStubWithExceptionPolicyAndTracing+0xd0 [onecore\com\combase\dcomrem\channelb.cxx @ 1277]
09 00007ffe`b53caaa6     : 00000226`e561a040 00007ffe`b4feb1f5 00000226`e5642450 00000000`00000000 : combase!DefaultStubInvoke+0x1ee [onecore\com\combase\dcomrem\channelb.cxx @ 1346]
0a (Inline Function)     : --------`-------- --------`-------- --------`-------- --------`-------- : combase!SyncStubCall::Invoke+0x22 [onecore\com\combase\dcomrem\channelb.cxx @ 1403]
0b 00007ffe`b5341283     : 00000226`e6a992f0 00000037`32c7e6f0 00000037`32c7e658 00000226`e5615d10 : combase!SyncServerCall::StubInvoke+0x26 [onecore\com\combase\dcomrem\ServerCall.hpp @ 781]
0c (Inline Function)     : --------`-------- --------`-------- --------`-------- --------`-------- : combase!StubInvoke+0x23e [onecore\com\combase\dcomrem\channelb.cxx @ 1628]
0d 00007ffe`b53c133d     : 00000037`32c7eeb0 00000226`e5678870 00000226`e56789c0 00007ffe`b53bc298 : combase!ServerCall::ContextInvoke+0x403 [onecore\com\combase\dcomrem\ctxchnl.cxx @ 1423]
0e (Inline Function)     : --------`-------- --------`-------- --------`-------- --------`-------- : combase!CServerChannel::ContextInvoke+0x70 [onecore\com\combase\dcomrem\ctxchnl.cxx @ 1332]
0f 00007ffe`b5335036     : 00000226`e5678870 00000037`32c7e9a0 00000000`00000000 00000226`e5f443c0 : combase!DefaultInvokeInApartment+0xad [onecore\com\combase\dcomrem\callctrl.cxx @ 3299]
10 (Inline Function)     : --------`-------- --------`-------- --------`-------- --------`-------- : combase!AppInvoke+0x245 [onecore\com\combase\dcomrem\channelb.cxx @ 1122]
11 00007ffe`b540b8cc     : 00007ffe`b5611f00 00000226`e5689900 00000226`e56522f4 00000226`e5689900 : combase!ComInvokeWithLockAndIPID+0xaf6 [onecore\com\combase\dcomrem\channelb.cxx @ 2210]
12 00007ffe`b5336ff9     : 00000037`32c7f0b0 00000000`00000000 00000226`e56fa6f0 00007ffe`b5554d48 : combase!ThreadInvokeWorker+0x7c4 [onecore\com\combase\dcomrem\channelb.cxx @ 7016]
13 00007ffe`b4fe9188     : 004000a0`00000032 00000037`32c7f090 00000226`004000a0 00000000`000e5f76 : combase!ThreadInvoke+0x9 [onecore\com\combase\dcomrem\channelb.cxx @ 7152]
14 00007ffe`b4fca3a6     : 00000226`e6abd350 000006c0`00000000 00000037`32c7f280 00000000`000006c0 : RPCRT4!DispatchToStubInCNoAvrf+0x18
15 00007ffe`b4fc9fd6     : 00000226`e56522a0 00000037`32c7f280 00000000`00000001 00000000`00000000 : RPCRT4!RPC_INTERFACE::DispatchToStubWorker+0x1a6
16 00007ffe`b4fd730f     : 00000000`00501100 00000226`000e6aa9 00000037`32c7f358 abababab`dededede : RPCRT4!RPC_INTERFACE::DispatchToStubWithObject+0x186
17 00007ffe`b4fd68c8     : 00000000`001000a6 00000000`00000001 00000000`00000000 00000226`e667a260 : RPCRT4!LRPC_SCALL::DispatchRequest+0x16f
18 00007ffe`b4fd5eb1     : 00000000`0000104c 00000226`e56fb870 00000000`00000000 00000000`00000000 : RPCRT4!LRPC_SCALL::HandleRequest+0x7f8
19 00007ffe`b4fd591e     : 00000000`00000000 00000000`00000000 00000000`00000001 00000226`e56321c0 : RPCRT4!LRPC_ADDRESS::HandleRequest+0x341
1a 00007ffe`b4fda032     : 00000000`00000001 00000226`e667a260 00000226`e56322c8 00000037`32c7f878 : RPCRT4!LRPC_ADDRESS::ProcessIO+0x89e
1b 00007ffe`b66b0330     : 00000001`00000000 00000000`00000000 00000037`32c7f878 00000000`00000676 : RPCRT4!LrpcIoComplete+0xc2
1c 00007ffe`b66e2f86     : 00000000`00000000 00000226`e5602300 00000000`00000000 00000226`e5f69cb0 : ntdll!TppAlpcpExecuteCallback+0x260
1d 00007ffe`b57a7614     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!TppWorkerThread+0x456
1e 00007ffe`b66e26b1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x14
1f 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21
	
	
	
iopl=0         nv up ei pl zr na po cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
tokenbroker!Windows::Internal::COperationLambdaVar<1,<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >::Run:
00007ffe`8ef5c3a0 4883ec28        sub     rsp,28h
0:006> kb
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef5a662     : 00007ffe`8f00e150 00007ffe`8ef4e7bf 00000226`e5f33308 00007ffe`8ef0d931 : tokenbroker!Windows::Internal::COperationLambdaVar<1,<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >::Run
01 00007ffe`8ef5ccab     : 00000226`e67e0040 00000226`e67e0040 00000037`32c7d740 00000037`32c7d710 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::OnStart+0x32
02 00007ffe`8ef4c6b7     : 00000226`e67e0040 00000037`32c7d870 00000037`32c7d790 00000037`32c7d790 : tokenbroker!Microsoft::WRL::AsyncBase<Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Microsoft::WRL::Details::Nil,1,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::Start+0x2b
03 00007ffe`8ef4c938     : 00000037`32c7d7c0 00000037`32c7d790 00007ffe`8f00e150 00000226`e6699780 : tokenbroker!Windows::Internal::MakeAsyncHelper<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::INilDelegate,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >+0x8b
04 00007ffe`8ef4c832     : 00000226`e5f33300 00000000`00000000 00000226`e67caf40 00000226`e564cc80 : tokenbroker!Windows::Internal::MakeStagedAsyncOperation<Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Security::Authentication::Web::Core::WebTokenRequestResult *,Windows::Internal::ComTaskPoolHandler,<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93> >+0x58
05 00007ffe`8ef5c0d1     : 00000226`e5f13e00 00000037`32c7dbd0 00000000`00000000 00000226`e5f13e00 : tokenbroker!Windows::Internal::Security::Authentication::Web::MakeAsyncWamOperation<Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation,TbLogProvider::TokenBrokerInternalRequestTokenAsync,Windows::Internal::Security::Authentication::Web::RequestTokenOperationParams,Windows::Security::Authentication::Web::Core::WebTokenRequestResult>+0x11e
06 00007ffe`b500b4b3     : 00000226`e5650a58 00000226`e6a3e130 00000226`e6804740 00000000`00000001 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerInternalFactory::RequestTokenAsync+0x6b1
07 00007ffe`b506e77b     : 00000037`32c7e098 00007ffe`971505f8 00000000`0000000e 00007ffe`971576f0 : RPCRT4!Invoke+0x73
08 00007ffe`b4fad479     : 00000226`e5678900 00000226`e68040c0 00000037`32c7e370 00007ffe`b53c7e4b : RPCRT4!Ndr64StubWorker+0xb0b
09 00007ffe`b53c5f1c     : 00000000`00000000 00000037`32c7e500 00007ffe`971576f0 00000226`e5642450 : RPCRT4!NdrStubCall3+0xc9
	


tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork:
00007ffe`8ef53cd0 48895c2408      mov     qword ptr [rsp+8],rbx ss:00000037`3317f810=0000000000000000
0:013> kb
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef4b294     : 00000000`00000000 00000037`3317f838 00000000`00000000 00000000`00000000 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork
01 00007ffe`8ef5c3b9     : 00000226`e67e0040 00000226`e573e640 00000000`00000000 00000000`00000001 : tokenbroker!<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>::operator()<Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >+0x60
02 00007ffe`8ef602fc     : 00000000`00000103 00000037`325b1000 00000000`00001cb4 00000000`00004698 : tokenbroker!Windows::Internal::COperationLambdaVar<1,<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >::Run+0x19
03 00007ffe`8ef5c389     : 00000226`e67e0108 00000037`3317fa80 00000000`00000000 00000226`e573e640 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::_Run+0xdc
04 00007ffe`b528d492     : 00000000`00000000 00000226`00000000 00000037`3317fa80 00000226`e573e640 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::Run+0x69
05 00007ffe`b5266d05     : 00000226`e573e710 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!WorkThreadManager::CThread::RunCurrentTaskUnderLock+0x62
06 00007ffe`b5266be0     : 00000000`00000001 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!WorkThreadManager::CThread::ThreadProc+0xf5
07 00007ffe`b52653e1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!WorkThreadManager::CThread::s_ExecuteThreadProc+0x18
08 00007ffe`b57a7614     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>+0x11
09 00007ffe`b66e26b1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x14
0a 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21


tokenbroker!Windows::Security::Authentication::Web::Provider::CWebAccountProviderActivatedEventArgs::get_Operation:
00007ffe`8ef9e230 48895c2408      mov     qword ptr [rsp+8],rbx ss:00000037`3317f510=00000226e56fccf8
0:013> kb 4
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef506e0     : 00000226`e56fccf8 00000000`00000000 00000226`e674df60 00007ffe`00000000 : tokenbroker!Windows::Security::Authentication::Web::Provider::CWebAccountProviderActivatedEventArgs::get_Operation
01 00007ffe`8ef58af8     : 00000000`00000000 00000000`00000000 00000000`00000000 00000226`e5f337b8 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::ActivateProvider+0x1c8
02 00007ffe`8ef53cec     : 00000037`3317f838 00000226`e67e19c0 00000226`e67caed0 00000000`00000000 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::LaunchProvider+0x300
03 00007ffe`8ef4b294     : 00000226`e67e19c0 00000037`3317f838 00000226`e5f36040 00000226`e5f36040 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork+0x1c

00007ffe`8ef50975 498b4538        mov     rax,qword ptr [r13+38h] ds:00007ffe`a2caa3a0={windows_internal_shellcommon_TokenBrokerModal!TokenBrokerModalImpl::ShowAndWaitForResponseWithSize (00007ffe`a2ca2b10)}
windows from "C:\WINDOWS\system32\wwahost.exe" -ServerName:App.wwa
C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\
C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\Microsoft.CloudExperienceHost.dll

0:008> kb 4
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef5097f     : 00000226`e6805140 00000000`00000000 00000226`e6805140 00000226`e66ba890 : windows_internal_shellcommon_TokenBrokerModal!TokenBrokerModalImpl::ShowAndWaitForResponseWithSize
01 00007ffe`8ef58af8     : 00000000`00000000 00000000`00000000 00000000`00000000 00000226`e5f32688 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::ActivateProvider+0x467
02 00007ffe`8ef53cec     : 00000037`32d7f888 00000226`e6a079c0 00000226`e68c14d0 00000000`00000000 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::LaunchProvider+0x300
03 00007ffe`8ef4b294     : 00000226`e6a079c0 00000037`32d7f888 00000226`e5f36860 00000226`e5f36860 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork+0x1c

C:\Windows\System32\windows.internal.shellcommon.TokenBrokerModal.dll

tokenbroker!Transform:
00007ffe`8ef5f15c 488bc4          mov     rax,rsp
0:008> kb
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef58b52     : 00000000`00000000 00000226`e5f329a8 00000000`00000000 00000226`e5f329a8 : tokenbroker!Transform
01 00007ffe`8ef53cec     : 00000037`32d7f368 00000226`e67e07c0 00000226`e5f66060 00000000`00000000 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::LaunchProvider+0x35a
02 00007ffe`8ef4b294     : 00000226`e67e07c0 00000037`32d7f368 00000226`e5f36ba0 00000226`e5f36ba0 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork+0x1c
03 00007ffe`8ef5c3b9     : 00000226`e67e07c0 00000226`e573e040 00000037`32d7f468 00000000`00000001 : tokenbroker!<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>::operator()<Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >+0x60
04 00007ffe`8ef602fc     : 00000000`00000103 00000037`325cf000 00000000`00001cb4 00000000`00003914 : tokenbroker!Windows::Internal::COperationLambdaVar<1,<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >::Run+0x19
05 00007ffe`8ef5c389     : 00000226`e67e0888 00000037`32d7f5b0 00000000`00000000 00000226`e573e040 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::_Run+0xdc
06 00007ffe`b528d492     : 00000000`00000000 00000226`00000000 00000037`32d7f5b0 00000226`e573e040 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::Run+0x69
07 00007ffe`b5266d05     : 00000226`e573e110 00000037`32d7f5b0 00000226`e573e040 00000000`00000000 : shcore!WorkThreadManager::CThread::RunCurrentTaskUnderLock+0x62
08 00007ffe`b5266be0     : 00000000`00000000 00000000`00000001 00000226`e5f86108 00000000`00000000 : shcore!WorkThreadManager::CThread::ThreadProc+0xf5
09 00007ffe`b52653e1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!WorkThreadManager::CThread::s_ExecuteThreadProc+0x18
0a 00007ffe`b57a7614     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>+0x11
0b 00007ffe`b66e26b1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x14
0c 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21

tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::HandleResult:
00007ffe`8ef57174 48895c2408      mov     qword ptr [rsp+8],rbx ss:00000037`32d7f160=0000000000000000
0:008>
0:008> kb
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef592ac     : 00000000`00000000 00000226`e5f757f0 00000226`e5f33308 00000037`80070057 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::HandleResult
01 00007ffe`8ef53cec     : 00000037`32d7f368 00000226`e68c0540 00000226`e5f666e0 00000000`00000000 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::LaunchProvider+0xab4
02 00007ffe`8ef4b294     : 00000226`e68c0540 00000037`32d7f368 00000226`e5f36520 00000226`e5f36520 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork+0x1c
03 00007ffe`8ef5c3b9     : 00000226`e68c0540 00000226`e573e040 00000226`e573e001 00000000`00000001 : tokenbroker!<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>::operator()<Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >+0x60
04 00007ffe`8ef602fc     : 00000000`00000103 00000037`325cf000 00000000`00001cb4 00000000`00003914 : tokenbroker!Windows::Internal::COperationLambdaVar<1,<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >::Run+0x19
05 00007ffe`8ef5c389     : 00000226`e68c0608 00000037`32d7f5b0 00000000`00000000 00000226`e573e040 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::_Run+0xdc
06 00007ffe`b528d492     : 00000000`00000000 00000226`00000000 00000037`32d7f5b0 00000226`e573e040 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::Run+0x69
07 00007ffe`b5266d05     : 00000226`e573e110 00000037`32d7f5b0 00000226`e573e040 00000000`00000000 : shcore!WorkThreadManager::CThread::RunCurrentTaskUnderLock+0x62
08 00007ffe`b5266be0     : 00000000`00000000 00000000`00000001 00000226`e68bf888 00000000`00000000 : shcore!WorkThreadManager::CThread::ThreadProc+0xf5
09 00007ffe`b52653e1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!WorkThreadManager::CThread::s_ExecuteThreadProc+0x18
0a 00007ffe`b57a7614     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>+0x11
0b 00007ffe`b66e26b1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x14
0c 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21
0:008> r
rax=0000000000000000 rbx=00000226e5f757f0 rcx=00000226e5f666e0
rdx=00000226e56d6650 rsi=00000226e5f33308 rdi=00007ffe8eedc501
rip=00007ffe8ef57174 rsp=0000003732d7f158 rbp=0000003732d7f260
 r8=0000000000000005  r9=00000226e56d0250 r10=0000000000400000
r11=0000000000200000 r12=0000000000000000 r13=00000226e5f66700
r14=0000000000000000 r15=00000226e5f666e0
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::HandleResult:
00007ffe`8ef57174 48895c2408      mov     qword ptr [rsp+8],rbx ss:00000037`32d7f160=0000000000000000

le 0000000000000005
private: long Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::HandleResult(struct Windows::Foundation::Collections::IVector<class Windows::Security::Authentication::Web::Core::WebTokenResponse *> *, enum Windows::Security::Authentication::Web::Core::WebTokenRequestStatus, struct Windows::Security::Authentication::Web::Core::IWebProviderError *, struct Windows::Foundation::DateTime, struct Windows::Storage::Streams::IBuffer *) proc near


tokenbroker!Transform:
00007ffe`8ef5f15c 488bc4          mov     rax,rsp
0:008> dq @r8
00000037`32d7f1d4  00000000`00000000 00000000`00000000
00000037`32d7f1e4  8eef7323`00000000 32d7f390`00007ffe
00000037`32d7f1f4  e6afd730`00000037 00000000`00000226
00000037`32d7f204  e5f03ac8`00000000 e5777710`00000226
00000037`32d7f214  e665b100`00000226 e68048c0`00000226
00000037`32d7f224  e68ef910`00000226 00000000`00000226
00000037`32d7f234  e54d0000`00000000 e5f03b28`00000226
00000037`32d7f244  e5777778`00000226 e5777720`00000226
0:008> gu
rax=0000000000000000 rbx=0000000000000000 rcx=00000226e5f03a80
rdx=0000000000000000 rsi=00000226e5f329a8 rdi=00000226e56cce10
rip=00007ffe8ef58b52 rsp=0000003732d7f160 rbp=0000003732d7f260
 r8=0000000000000280  r9=0000000000000006 r10=00000226e5f03a80
r11=0000000005400010 r12=00007ffe8eff6308 r13=00000226e6804470
r14=0000000000000000 r15=00000226e6804450
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::LaunchProvider+0x35a:
00007ffe`8ef58b52 89442440        mov     dword ptr [rsp+40h],eax ss:00000037`32d7f1a0=00000000
0:008> dq 00000037`32d7f1d4
00000037`32d7f1d4  00000000`00000005 e5f75400`00000000
00000037`32d7f1e4  8eef7323`00000226 32d7f390`00007ffe
00000037`32d7f1f4  e6afd730`00000037 e66bd6a0`00000226
00000037`32d7f204  e5f03ac8`00000226 e5777710`00000226
00000037`32d7f214  e665b100`00000226 e68048c0`00000226
00000037`32d7f224  e68ef910`00000226 00000000`00000226
00000037`32d7f234  e54d0000`00000000 e5f03b28`00000226
00000037`32d7f244  e5777778`00000226 e5777720`00000226

tokenbroker!Windows::Security::Authentication::Web::Core::CWebProviderError::get_Properties:
00007ffe`8efc01a0 48895c2408      mov     qword ptr [rsp+8],rbx ss:00000037`32d7f080=0000000000000000
0:008> kb 4
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef5f5f4     : 00000000`00000000 00000226`e5f031a0 00000226`e6afe230 00007ffe`8ef9a5d1 : tokenbroker!Windows::Security::Authentication::Web::Core::CWebProviderError::get_Properties
01 00007ffe`8ef58b52     : 00000000`00000000 00000037`32d7f200 00000000`00000000 00000037`80070057 : tokenbroker!Transform+0x498
02 00007ffe`8ef53cec     : 00000037`32d7f368 00000226`e6783240 00000226`e67ca0d0 00000000`00000000 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::LaunchProvider+0x35a
03 00007ffe`8ef4b294     : 00000226`e6783240 00000037`32d7f368 00000226`e5f36ba0 00000226`e5f36ba0 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork+0x1c

0:008> bm tokenbroker!Windows::Security::Authentication::Web::Core::CWebProviderError::get_ErrorCode
breakpoint 15 redefined
 15: 00007ffe`8eefd9f0 @!"tokenbroker!Windows::Security::Authentication::Web::Core::CWebProviderError::get_ErrorCode"
0:008> g
Breakpoint 15 hit
rax=00007ffe8eefd9f0 rbx=0000000000000000 rcx=00000226e5f74b90
rdx=0000003732d7f278 rsi=00000226e5f33308 rdi=0000200000000000
rip=00007ffe8eefd9f0 rsp=0000003732d7f1e8 rbp=0000003732d7f2f0
 r8=0000000000000000  r9=0000000000000002 r10=00000fffd1ddfb3e
r11=4455444444000000 r12=00007ffe8eff6308 r13=00000226e6abca70
r14=0000000000000000 r15=00000226e6abca50
iopl=0         nv up ei pl zr na po cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
tokenbroker!Windows::Security::Authentication::Web::Core::CWebProviderError::get_ErrorCode:
00007ffe`8eefd9f0 8b4158          mov     eax,dword ptr [rcx+58h] ds:00000226`e5f74be8=80070057
0:008> kb
 # RetAddr               : Args to Child                                                           : Call Site
00 00007ffe`8ef58c24     : 00000000`00000000 00000037`32d7f290 00000000`00000000 00000037`80070057 : tokenbroker!Windows::Security::Authentication::Web::Core::CWebProviderError::get_ErrorCode
01 00007ffe`8ef53cec     : 00000037`32d7f3f8 00000226`e67220c0 00000226`e6abca50 00000000`00000000 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::LaunchProvider+0x42c
02 00007ffe`8ef4b294     : 00000226`e67220c0 00000037`32d7f3f8 00000226`e5f36d40 00000226`e5f36d40 : tokenbroker!Windows::Internal::Security::Authentication::Web::CTokenBrokerOperation::DoWork+0x1c
03 00007ffe`8ef5c3b9     : 00000226`e67220c0 00000226`e573ee40 00000226`e573ee01 00000000`00000001 : tokenbroker!<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>::operator()<Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >+0x60
04 00007ffe`8ef602fc     : 00000000`00000103 00000037`32464000 00000000`00001cb4 00000000`000025d0 : tokenbroker!Windows::Internal::COperationLambdaVar<1,<lambda_a94ba5d0f87cb9dafc6445b1ca8a4d93>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> >::Run+0x19
05 00007ffe`8ef5c389     : 00000226`e6722188 00000037`32d7f640 00000000`00000000 00000226`e573ee40 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::_Run+0xdc
06 00007ffe`b528d492     : 00000000`00000000 00000226`00000000 00000037`32d7f640 00000226`e573ee40 : tokenbroker!Windows::Internal::AsyncOperation<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Foundation::IAsyncOperationCompletedHandler<Windows::Security::Authentication::Web::Core::WebTokenRequestResult * __ptr64>,Windows::Internal::CMarshaledInterfaceResult<Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>,Windows::Internal::ComTaskPoolHandler,Windows::Internal::INilDelegate,Microsoft::WRL::AsyncOptions<-1,0,&GUID_CAUSALITY_WINDOWS_PLATFORM_ID,2> >::Run+0x69
07 00007ffe`b5266d05     : 00000226`e573ef10 00000037`32d7f640 00000226`e573ee40 00000000`00000000 : shcore!WorkThreadManager::CThread::RunCurrentTaskUnderLock+0x62
08 00007ffe`b5266be0     : 00000000`00000000 00000000`00000001 00000226`e6721b88 00000000`00000000 : shcore!WorkThreadManager::CThread::ThreadProc+0xf5
09 00007ffe`b52653e1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!WorkThreadManager::CThread::s_ExecuteThreadProc+0x18
0a 00007ffe`b57a7614     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : shcore!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>+0x11
0b 00007ffe`b66e26b1     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x14
0c 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21
0:008> dq @rcx
00000226`e5f74b90  00007ffe`8efdf458 00007ffe`8efdf438
00000226`e5f74ba0  00007ffe`8efdf408 00007ffe`8efdf3d8
00000226`e5f74bb0  00007ffe`8efdf360 00000226`e5f74d48
00000226`e5f74bc0  00000226`e5f74d40 00000226`e6769380
00000226`e5f74bd0  00007ffe`8efdf328 00000000`00000000
00000226`e5f74be0  00000000`00000001 00000000`80070057
00000226`e5f74bf0  00000226`e66ccb00 00000226`e6870710
00000226`e5f74c00  00000000`00000001 00000000`00000000
0:008> dq  00000226`e66ccb00
00000226`e66ccb00  00000135`00000000 00008000`99dead99
00000226`e66ccb10  00000226`e66ccb1c 00680054`00000001
00000226`e66ccb20  00610070`00200065 0065006d`00610072
00000226`e66ccb30  00200072`00650074 00690020`00730069
00000226`e66ccb40  0072006f`0063006e 00740063`00650072
00000226`e66ccb50  000d000a`000d002e 0065006e`006f000a
00000226`e66ccb60  00650072`006f0063 005c0070`00610075
00000226`e66ccb70  006c0065`00680073 006c0063`005c006c
0:008> du 00000226`e66ccb1c
00000226`e66ccb1c  "The parameter is incorrect.....o"
00000226`e66ccb5c  "necoreuap\shell\cloudexperienceh"
00000226`e66ccb9c  "ost\onecore\app\msa\core\TokenRe"
00000226`e66ccbdc  "questParams.cpp(153)\MicrosoftAc"
00000226`e66ccc1c  "count.TokenProvider.Core.dll!000"
00000226`e66ccc5c  "07FFE9D9A19FB: (caller: 00007FFE"
00000226`e66ccc9c  "9D9AFE3D) Exception(1) tid(10ec)"
00000226`e66cccdc  " 80070057 The parameter is incor"
00000226`e66ccd1c  "rect...    CallContext:[\Request"
00000226`e66ccd5c  "TokenAsyncActivity] ."

C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\MicrosoftAccount.TokenProvider.Core.dll

in wwahost.exe

0	ntoskrnl.exe	PsCallImageNotifyRoutines + 0x165	0xfffff80075428c85	C:\WINDOWS\system32\ntoskrnl.exe
1	ntoskrnl.exe	MiMapViewOfImageSection + 0x74d	0xfffff80075427b2d	C:\WINDOWS\system32\ntoskrnl.exe
2	ntoskrnl.exe	MiMapViewOfSection + 0x3fc	0xfffff8007542234c	C:\WINDOWS\system32\ntoskrnl.exe
3	ntoskrnl.exe	NtMapViewOfSection + 0x159	0xfffff80075421de9	C:\WINDOWS\system32\ntoskrnl.exe
4	ntoskrnl.exe	KiSystemServiceCopyEnd + 0x25	0xfffff8007520f8f5	C:\WINDOWS\system32\ntoskrnl.exe
5	ntdll.dll	NtMapViewOfSection + 0x14	0x7ffeb672d4e4	C:\Windows\System32\ntdll.dll
6	ntdll.dll	LdrpMinimalMapModule + 0x10a	0x7ffeb66a4d42	C:\Windows\System32\ntdll.dll
7	ntdll.dll	LdrpMapDllWithSectionHandle + 0x1a	0x7ffeb66a4aaa	C:\Windows\System32\ntdll.dll
8	ntdll.dll	LdrpMapDllNtFileName + 0x19f	0x7ffeb66efd93	C:\Windows\System32\ntdll.dll
9	ntdll.dll	LdrpMapDllFullPath + 0xe0	0x7ffeb66efac0	C:\Windows\System32\ntdll.dll
10	ntdll.dll	LdrpProcessWork + 0x123	0x7ffeb66eed5f	C:\Windows\System32\ntdll.dll
11	ntdll.dll	LdrpLoadDllInternal + 0x13f	0x7ffeb66afb53	C:\Windows\System32\ntdll.dll
12	ntdll.dll	LdrpLoadDll + 0xa8	0x7ffeb66a73e4	C:\Windows\System32\ntdll.dll
13	ntdll.dll	LdrLoadDll + 0xe4	0x7ffeb66a6af4	C:\Windows\System32\ntdll.dll
14	KernelBase.dll	LoadLibraryExW + 0x162	0x7ffeb41a56b2	C:\Windows\System32\KernelBase.dll
15	combase.dll	LoadLibraryWithLogging + 0x2d, onecore\com\combase\common\internal\loadfree.cxx(158)	0x7ffeb5366b6d	C:\Windows\System32\combase.dll
16	combase.dll	CClassCache::CDllPathEntry::LoadDll + 0x56, onecore\com\combase\objact\dllcache.cxx(2294)	0x7ffeb5366ab6	C:\Windows\System32\combase.dll
17	combase.dll	CClassCache::CDllPathEntry::Create + 0x58, onecore\com\combase\objact\dllcache.cxx(2123)	0x7ffeb5366888	C:\Windows\System32\combase.dll
18	combase.dll	CClassCache::GetOrLoadWinRTInprocClass + 0x509, onecore\com\combase\objact\dllcache.cxx(4799)	0x7ffeb533a139	C:\Windows\System32\combase.dll
19	combase.dll	_RoGetActivationFactory + 0x425, onecore\com\combase\winrtbase\winrtbase.cpp(963)	0x7ffeb533c5e5	C:\Windows\System32\combase.dll
20	edgehtml.dll	CScriptHostContext::CreateTypeFactoryInstance + 0x7e	0x7ffe63dc646e	C:\Windows\System32\edgehtml.dll
21	Chakra.dll	Projection::ProjectionContext::CreateTypeFactoryInstance + 0x99	0x7ffe7d6d3655	C:\Windows\System32\Chakra.dll
22	Chakra.dll	Projection::FastPathPopulateRuntimeClassThis + 0x99	0x7ffe7d6d347d	C:\Windows\System32\Chakra.dll
23	Chakra.dll	<lambda_afe065cfe82e6c90c8c73bd99c22fe6d>::operator() + 0x4e	0x7ffe7d80aca6	C:\Windows\System32\Chakra.dll
24	Chakra.dll	Projection::TryGetProjectionFastPath + 0x139daf	0x7ffe7d76a053	C:\Windows\System32\Chakra.dll
25	Chakra.dll	Projection::ProjectionWriter::ContinueFunctionOfSignature + 0xc8	0x7ffe7d630148	C:\Windows\System32\Chakra.dll
26	Chakra.dll	Projection::ProjectionWriter::DelayedFunctionOfSignatureThunk + 0x77	0x7ffe7d62ffe7	C:\Windows\System32\Chakra.dll
27	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
28	Chakra.dll	Js::JavascriptFunction::CallAsConstructor + 0x2d0	0x7ffe7d54f0e0	C:\Windows\System32\Chakra.dll
29	Chakra.dll	Js::ProfilingHelpers::ProfiledNewScObject + 0x245	0x7ffe7d54ec05	C:\Windows\System32\Chakra.dll
30	Chakra.dll	Js::InterpreterStackFrame::ProfiledNewScObject_Helper + 0x9d	0x7ffe7d54e86d	C:\Windows\System32\Chakra.dll
31	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledNewScObjectWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0x44	0x7ffe7d861270	C:\Windows\System32\Chakra.dll
32	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0xb3f	0x7ffe7d5f957f	C:\Windows\System32\Chakra.dll
33	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
34	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
35	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
36	<unknown>	0x21ea645170a	0x21ea645170a
37	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
38	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x2db	0x7ffe7d5fc02b	C:\Windows\System32\Chakra.dll
39	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
40	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
41	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
42	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
43	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
44	<unknown>	0x21ea6451802	0x21ea6451802
45	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
46	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > > + 0x182	0x7ffe7d67c572	C:\Windows\System32\Chakra.dll
47	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallI<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > + 0xb7	0x7ffe7d67c397	C:\Windows\System32\Chakra.dll
48	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x55c	0x7ffe7d5f8f9c	C:\Windows\System32\Chakra.dll
49	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
50	Chakra.dll	Js::InterpreterStackFrame::OP_TryCatch + 0xda	0x7ffe7d663d9a	C:\Windows\System32\Chakra.dll
51	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0xf4c	0x7ffe7d5f998c	C:\Windows\System32\Chakra.dll
52	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
53	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
54	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
55	<unknown>	0x21ea6451eaa	0x21ea6451eaa
56	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
57	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x182	0x7ffe7d5fbed2	C:\Windows\System32\Chakra.dll
58	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
59	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
60	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
61	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
62	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
63	<unknown>	0x21ea645183a	0x21ea645183a
64	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
65	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > > + 0x182	0x7ffe7d67c572	C:\Windows\System32\Chakra.dll
66	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallI<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > + 0xb7	0x7ffe7d67c397	C:\Windows\System32\Chakra.dll
67	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x55c	0x7ffe7d5f8f9c	C:\Windows\System32\Chakra.dll
68	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
69	Chakra.dll	Js::InterpreterStackFrame::OP_TryCatch + 0xda	0x7ffe7d663d9a	C:\Windows\System32\Chakra.dll
70	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0xf4c	0x7ffe7d5f998c	C:\Windows\System32\Chakra.dll
71	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
72	Chakra.dll	Js::InterpreterStackFrame::ProcessTryFinally + 0xac	0x7ffe7d5e7ddc	C:\Windows\System32\Chakra.dll
73	Chakra.dll	Js::InterpreterStackFrame::OP_TryFinally + 0x2c	0x7ffe7d868bb4	C:\Windows\System32\Chakra.dll
74	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x5ec	0x7ffe7d5f902c	C:\Windows\System32\Chakra.dll
75	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
76	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
77	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
78	<unknown>	0x21ea6451f62	0x21ea6451f62
79	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
80	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x2db	0x7ffe7d5fc02b	C:\Windows\System32\Chakra.dll
81	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
82	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
83	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
84	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
85	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
86	<unknown>	0x21ea6451f6a	0x21ea6451f6a
87	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
88	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x2db	0x7ffe7d5fc02b	C:\Windows\System32\Chakra.dll
89	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
90	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
91	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
92	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
93	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
94	<unknown>	0x21ea6450cba	0x21ea6450cba
95	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
96	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x2db	0x7ffe7d5fc02b	C:\Windows\System32\Chakra.dll
97	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
98	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
99	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
100	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
101	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
102	<unknown>	0x21ea6451f7a	0x21ea6451f7a
103	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
104	Chakra.dll	Js::BoundFunction::NewInstance + 0x166	0x7ffe7d472b26	C:\Windows\System32\Chakra.dll
105	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
106	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > > + 0x2c3	0x7ffe7d67c6b3	C:\Windows\System32\Chakra.dll
107	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallI<Js::OpLayoutT_CallI<Js::LayoutSizePolicy<0> > > + 0xb7	0x7ffe7d67c397	C:\Windows\System32\Chakra.dll
108	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x55c	0x7ffe7d5f8f9c	C:\Windows\System32\Chakra.dll
109	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
110	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
111	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
112	<unknown>	0x21ea6451842	0x21ea6451842
113	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
114	Chakra.dll	Js::JavascriptFunction::CallFunction<1> + 0xe2	0x7ffe7d5d53c2	C:\Windows\System32\Chakra.dll
115	Chakra.dll	Js::JavascriptFunction::CalloutHelper<0> + 0x1ca	0x7ffe7d5d4c7a	C:\Windows\System32\Chakra.dll
116	Chakra.dll	Js::JavascriptFunction::EntryApply + 0x11f	0x7ffe7d5d4a8f	C:\Windows\System32\Chakra.dll
117	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
118	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x182	0x7ffe7d5fbed2	C:\Windows\System32\Chakra.dll
119	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
120	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
121	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
122	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
123	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
124	<unknown>	0x21ea6451c22	0x21ea6451c22
125	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
126	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x182	0x7ffe7d5fbed2	C:\Windows\System32\Chakra.dll
127	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
128	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
129	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
130	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
131	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
132	<unknown>	0x21ea6451d4a	0x21ea6451d4a
133	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
134	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x182	0x7ffe7d5fbed2	C:\Windows\System32\Chakra.dll
135	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
136	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
137	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll
138	Chakra.dll	Js::InterpreterStackFrame::InterpreterHelper + 0x4e6	0x7ffe7d5e9d06	C:\Windows\System32\Chakra.dll
139	Chakra.dll	Js::InterpreterStackFrame::InterpreterThunk + 0x4e	0x7ffe7d5e91ee	C:\Windows\System32\Chakra.dll
140	<unknown>	0x21ea6451a8a	0x21ea6451a8a
141	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
142	Chakra.dll	Js::JavascriptFunction::CallFunction<1> + 0xe2	0x7ffe7d5d53c2	C:\Windows\System32\Chakra.dll
143	Chakra.dll	Js::JavascriptFunction::CalloutHelper<0> + 0x1ca	0x7ffe7d5d4c7a	C:\Windows\System32\Chakra.dll
144	Chakra.dll	Js::JavascriptFunction::EntryApply + 0x11f	0x7ffe7d5d4a8f	C:\Windows\System32\Chakra.dll
145	Chakra.dll	amd64_CallFunction + 0x86	0x7ffe7d6f35c6	C:\Windows\System32\Chakra.dll
146	Chakra.dll	Js::InterpreterStackFrame::OP_CallCommon<Js::OpLayoutDynamicProfile<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > > + 0x182	0x7ffe7d5fbed2	C:\Windows\System32\Chakra.dll
147	Chakra.dll	Js::InterpreterStackFrame::OP_ProfiledCallIWithICIndex<Js::OpLayoutT_CallIWithICIndex<Js::LayoutSizePolicy<0> > > + 0xb8	0x7ffe7d5f7928	C:\Windows\System32\Chakra.dll
148	Chakra.dll	Js::InterpreterStackFrame::ProcessProfiled + 0x203	0x7ffe7d5f8c43	C:\Windows\System32\Chakra.dll
149	Chakra.dll	Js::InterpreterStackFrame::Process + 0x108	0x7ffe7d5eb088	C:\Windows\System32\Chakra.dll


	*/
	//Sleep(10 * 1000);
end:
	if (acidString != NULL)
		WindowsDeleteString(acidString);

	return (int)Res;
}


