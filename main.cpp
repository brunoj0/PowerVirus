#include "stdafx.h"
#define _WIN32_DCOM
#include <iostream>
#include <windows.h>
#include <process.h>
#include <time.h>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
# pragma comment(lib, "wbemuuid.lib")

#define CRED_MAX_USERNAME_LENGTH            513
#define CRED_MAX_CREDENTIAL_BLOB_SIZE       512
#define CREDUI_MAX_USERNAME_LENGTH CRED_MAX_USERNAME_LENGTH
#define CREDUI_MAX_PASSWORD_LENGTH (CRED_MAX_CREDENTIAL_BLOB_SIZE / 2)

union vector 
{
	_declspec(align(128)) float x;
	float f[4];
};

void functionFLT(float *s)
{
	;
}

void functionINT(int *a)
{
	;
}

void function()
{
	;
}



void myFunction(void * dummy) {

	cout << "Dzialam \n";
	_endthread();
}
void myFunction1(void * dummy) {

	cout << "Aby zakonczyc wcisnij dowolny klawisz \n";
	_endthread();

}
void myFunction2(void * dummy) {
	system("taskmgr");
	_endthread();
}
void myFunction3(void * dummy) {
	//    int sekudny = 240;
	clock_t koniec_czekania;
	koniec_czekania = clock() + 120 * CLOCKS_PER_SEC;

	union vector a, b, c;
	a.f[0] = 1; a.f[1] = 2; a.f[2] = 3; a.f[3] = 4;
	b.f[0] = 5; b.f[1] = 6; b.f[2] = 7; b.f[3] = 8;

	int* i = 0;
	float* p;
	float s = 1;
	int x = 0;
	int A[10000] = { 0 };
	int B[100];


	for (int j = 0; j < 100; j++)
		B[j] = rand() % 1000000;

	while (clock() < koniec_czekania)
	{

		(*i++) + 1;
		A[B[x++]];
		char tab[4] = "CPU";

		functionINT(&x);
		functionFLT(&s);
		function();


		__asm mov eax, 5345
		__asm mov ecx, 9353
		__asm add ecx, eax


		__asm mov eax, 5345
		__asm mov ecx, 9353
		__asm sub ecx, eax

		__asm mov eax, 5345
		__asm mov ecx, 9353
		__asm imul ecx, eax


		c.x = a.x + b.x;

		if (x == 100) x = 0;

	}


	_endthread();
}

#pragma argsused
int main(int argc, char* argv[])
{
	wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"user";
	wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"password";
	BSTR strNetworkResource;
	//To use a WMI remote connection set localconn to false and configure the values of the pszName, pszPwd and the name of the remote machine in strNetworkResource
	bool localconn = true;
	strNetworkResource = localconn ? L"\\\\.\\root\\CIMV2" : L"\\\\remote--machine\\root\\CIMV2";

	COAUTHIDENTITY *userAcct = NULL;
	COAUTHIDENTITY authIdent;

	// Initialize COM. ------------------------------------------

	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x" << hex << hres << endl;
		cout << _com_error(hres).ErrorMessage() << endl;
		cout << "press enter to exit" << endl;
		cin.get();
		return 1;                  // Program has failed.
	}

	// Set general COM security levels --------------------------

	if (localconn)
		hres = CoInitializeSecurity(
			NULL,
			-1,                          // COM authentication
			NULL,                        // Authentication services
			NULL,                        // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
			RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
			NULL,                        // Authentication info
			EOAC_NONE,                   // Additional capabilities
			NULL                         // Reserved
			);
	else
		hres = CoInitializeSecurity(
			NULL,
			-1,                          // COM authentication
			NULL,                        // Authentication services
			NULL,                        // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
			RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation
			NULL,                        // Authentication info
			EOAC_NONE,                   // Additional capabilities
			NULL                         // Reserved
			);

	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x" << hex << hres << endl;
		cout << _com_error(hres).ErrorMessage() << endl;
		CoUninitialize();
		cout << "press enter to exit" << endl;
		cin.get();
		return 1;                    // Program has failed.
	}

	// Obtain the initial locator to WMI -------------------------

	IWbemLocator *pLoc = NULL;
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object." << " Err code = 0x" << hex << hres << endl;
		cout << _com_error(hres).ErrorMessage() << endl;
		CoUninitialize();
		cout << "press enter to exit" << endl;
		cin.get();
		return 1;                 // Program has failed.
	}

	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices *pSvc = NULL;

	if (localconn)
		hres = pLoc->ConnectServer(
			_bstr_t(strNetworkResource),      // Object path of WMI namespace
			NULL,                    // User name. NULL = current user
			NULL,                    // User password. NULL = current
			0,                       // Locale. NULL indicates current
			NULL,                    // Security flags.
			0,                       // Authority (e.g. Kerberos)
			0,                       // Context object
			&pSvc                    // pointer to IWbemServices proxy
			);
	else
		hres = pLoc->ConnectServer(
			_bstr_t(strNetworkResource),  // Object path of WMI namespace
			_bstr_t(pszName),             // User name
			_bstr_t(pszPwd),              // User password
			NULL,                // Locale
			NULL,                // Security flags
			NULL,				 // Authority
			NULL,                // Context object
			&pSvc                // IWbemServices proxy
			);

	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x" << hex << hres << endl;
		cout << _com_error(hres).ErrorMessage() << endl;
		pLoc->Release();
		CoUninitialize();
		cout << "press enter to exit" << endl;
		cin.get();
		return 1;                // Program has failed.
	}


	// Set security levels on the proxy -------------------------
	if (localconn)
		hres = CoSetProxyBlanket(
			pSvc,                        // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
			NULL,                        // Server principal name
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			NULL,                        // client identity
			EOAC_NONE                    // proxy capabilities
			);
	else
	{
		// Create COAUTHIDENTITY that can be used for setting security on proxy
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;
		authIdent.User = (USHORT*)pszName;
		authIdent.UserLength = wcslen(pszName);
		authIdent.Domain = 0;
		authIdent.DomainLength = 0;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
		userAcct = &authIdent;

		hres = CoSetProxyBlanket(
			pSvc,                           // Indicates the proxy to set
			RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
			COLE_DEFAULT_PRINCIPAL,         // Server principal name
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx
			RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
			userAcct,                       // client identity
			EOAC_NONE                       // proxy capabilities
			);
	}

	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
		cout << _com_error(hres).ErrorMessage() << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		cout << "press enter to exit" << endl;
		cin.get();
		return 1;               // Program has failed.
	}

	// Use the IWbemServices pointer to make requests of WMI ----

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(L"WQL", L"SELECT * FROM Win32_Processor",
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hres))
	{
		cout << "ExecQuery failed" << " Error code = 0x" << hex << hres << endl;
		cout << _com_error(hres).ErrorMessage() << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		cout << "press enter to exit" << endl;
		cin.get();
		return 1;               // Program has failed.
	}

	// Secure the enumerator proxy
	if (!localconn)
	{

		hres = CoSetProxyBlanket(
			pEnumerator,                    // Indicates the proxy to set
			RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
			COLE_DEFAULT_PRINCIPAL,         // Server principal name
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx
			RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
			userAcct,                       // client identity
			EOAC_NONE                       // proxy capabilities
			);

		if (FAILED(hres))
		{
			cout << "Could not set proxy blanket on enumerator. Error code = 0x" << hex << hres << endl;
			cout << _com_error(hres).ErrorMessage() << endl;
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			cout << "press enter to exit" << endl;
			cin.get();
			return 1;               // Program has failed.
		}
	}

	// Get the data from the WQL sentence
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn || FAILED(hr))
			break;

		VARIANT vtProp;

		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);// String
		if (!FAILED(hr))
		{
			if ((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY))
				wcout << "Nazwa procesora : " << ((vtProp.vt == VT_NULL) ? "NULL" : "EMPTY") << endl;
			else
				if ((vtProp.vt & VT_ARRAY))
					wcout << "Nazwa procesora : " << "Array types not supported (yet)" << endl;
				else
					wcout << "Nazwa procesora : " << vtProp.bstrVal << endl;
		}
		VariantClear(&vtProp);

		hr = pclsObj->Get(L"NumberOfCores", 0, &vtProp, 0, 0);// Uint32
		if (!FAILED(hr))
		{
			if ((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY))
				wcout << "Liczba rdzeni : " << ((vtProp.vt == VT_NULL) ? "NULL" : "EMPTY") << endl;
			else
				if ((vtProp.vt & VT_ARRAY))
					wcout << "Liczba rdzeni : " << "Array types not supported (yet)" << endl;
				else
					wcout << "Liczba rdzeni : " << vtProp.uintVal << endl;
		}
		VariantClear(&vtProp);

		hr = pclsObj->Get(L"NumberOfLogicalProcessors", 0, &vtProp, 0, 0);// Uint32
		if (!FAILED(hr))
		{
			if ((vtProp.vt == VT_NULL) || (vtProp.vt == VT_EMPTY))
				wcout << "Liczba watkow : " << ((vtProp.vt == VT_NULL) ? "NULL" : "EMPTY") << endl;
			else
				if ((vtProp.vt & VT_ARRAY))
					wcout << "Liczba watkow : " << "Array types not supported (yet)" << endl;
				else
					wcout << "Liczba watkow : " << vtProp.uintVal << endl;

		}



		int liczba = vtProp.uintVal;
		int start;
		cout << endl << "Startujemy? " << endl;
		cout << "1.TAK " << endl;
		cout << "2.NIE " << endl;
		cin >> start;
		if (start == 1)
		{

			if (liczba == 1) {
				//uruchomienie wątku
				_beginthread(myFunction, 0, 0);
				_beginthread(myFunction1, 0, 0);
				_beginthread(myFunction2, 0, 0);
				// I wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
			}
			if (liczba == 2) {
				//uruchomienie wątku
				_beginthread(myFunction, 0, 0);
				_beginthread(myFunction1, 0, 0);
				_beginthread(myFunction2, 0, 0);
				// I wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// II wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
			}
			if (liczba == 3) {
				_beginthread(myFunction, 0, 0);
				_beginthread(myFunction1, 0, 0);
				_beginthread(myFunction2, 0, 0);
				// I wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// II wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// III wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
			}
			if (liczba == 4) {
				_beginthread(myFunction, 0, 0);
				_beginthread(myFunction1, 0, 0);
				_beginthread(myFunction2, 0, 0);
				// I wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// II wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// III wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// IV wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
			}
			if (liczba == 8) {
				_beginthread(myFunction, 0, 0);
				_beginthread(myFunction1, 0, 0);
				_beginthread(myFunction2, 0, 0);
				// I wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// II wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// III wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// IV wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// V wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// VI wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// VII wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
				// VIII wątek dla obciążenia procesora
				_beginthread(myFunction3, 0, 0);
			}
		}
		else
		{
			system("PAUSE");
			return 0;
		}

		VariantClear(&vtProp);


		pclsObj->Release();
		pclsObj = NULL;
	}

	// Cleanup

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	if (pclsObj != NULL)
		pclsObj->Release();

	CoUninitialize();

	system("PAUSE");
	return 0;




}
(cc) 2006-2012 ForgottenLabs.com
