/*++

Copyright (c) 2013, 2014  Microsoft Corporation
Microsoft Confidential

*/
#include "stdafx.h"
#include "Tpm2.h"

using namespace TpmCpp;

// #include "Samples.h"
#include "TpmCppWrapper.h"

// The name "DllInit" is misleading on non-WIN32 platforms but
// the purpose of the routine is the same, initializing TSS.CPP.
extern void DllInit();

#ifdef WIN32
_CrtMemState MemState;

int _tmain(int argc, _TCHAR *argv[])
{
    _CrtMemCheckpoint(&MemState);

    Samples s;
    s.RunAllSamples();

    HMODULE h = LoadLibrary(_T("TSS.CPP.dll"));
    _ASSERT(h != NULL);

    BOOL ok = FreeLibrary(h);
    _ASSERT(ok);
    _CrtMemDumpAllObjectsSince(&MemState);

    return 0;
}
#endif

#ifdef __linux__
int main(int argc, char *argv[])
{
    // DllInit();

    try {
        // Samples s;
        // s.RunAllSamples();
        TpmCppWrapper t("/etc/azuredm/agentcert.pem");

        const char* privateKey = t.GetPrivateKey();
        printf("\nPrivate key= %s\n", privateKey);

        int result = t.Createx509SelfSignedCert();
                
        if(result == 0)
        {
            printf("\nx509 certificate created successfully.\n");
        }
        else
        {
            printf("\nx509 certificate creation failed.\n");
        }

        const char* x509Certificate = t.GetX509Cert();

        if(!x509Certificate)
        {
            printf("x509 certificate does not exist\n");
        }
        else
        {
            printf("read x509 certificate=%s\n", x509Certificate);
        }
    }
    catch (const runtime_error& exc) {
        cerr << "TpmCppTester: " << exc.what() << "\nExiting...\n";
    }

    return 0;
}
#endif