
#include "Tpm2.h"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
// #include "CryptoServices.h"
#include "TpmCppWrapper.h"

using namespace TpmCpp;

// The name "DllInit" is misleading on non-WIN32 platforms but
// the purpose of the routine is the same, initializing TSS.CPP.
extern void DllInit();

// Tpm2 tpm;
// TpmTcpDevice device;

// Initialize the library and local TPM
TpmCppWrapper::TpmCppWrapper(const string &certFilePath):
    _certFilePath(certFilePath)
{
    DllInit();
    
    // Connect the Tpm2 device to a simulator running on the same machine
    if (!device.Connect("127.0.0.1", 2321)) {
        cerr << "Could not connect to the TPM device";
        return;
    }

    // Instruct the Tpm2 object to send commands to the local TPM simulator
    tpm._SetDevice(device);

    // Power-cycle the simulator
    device.PowerOff();
    device.PowerOn();

    // and startup the TPM
    tpm.Startup(TPM_SU::CLEAR);

    _DeriveRsaKeyFromTpm();

    return;
}

void TpmCppWrapper::_DeriveRsaKeyFromTpm()
{
    PolicyTree p(PolicyCommandCode(TPM_CC::Duplicate, ""));
    TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA256);

    // Setting the null auth.
    ByteVec userAuth = ByteVec{};
    vector<BYTE> NullVec;
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, NullVec);

    // Create primary key template.
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sensitiveDataOrigin | // object was created with TPM2_Create or TPM2_CreatePrimary.
        TPMA_OBJECT::userWithAuth | // approval of user role actions with policy session.
                                    // TPMA_OBJECT::adminWithPolicy | // approval admin role actions with policy session only.
        TPMA_OBJECT::noDA | // not subject to dictionary attack protection.
        // TPMA_OBJECT::encryptedDuplication - CLEAR the object can be duplicated without inner wrapper on private portion of the key.
        TPMA_OBJECT::decrypt |
        TPMA_OBJECT::sign,
        policyDigest.digest,
        TPMS_RSA_PARMS(    // How child keys should be protected
            TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::_NULL, 0, TPM_ALG_ID::_NULL),
            TPMS_NULL_ASYM_SCHEME(),
            2048,
            65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    // Create primary key.
    CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(tpm._AdminOwner,
        sensCreate,
        storagePrimaryTemplate,
        NullVec,
        vector<TPMS_PCR_SELECTION>());

    // Added for debugging.
    cout << "New RSA primary key public portion" << endl << storagePrimary.outPublic.ToString(true) << endl;

    cout << "Name of new key:" << endl;
    cout << " Returned by TPM " << storagePrimary.name << endl;
    cout << " Calculated      " << storagePrimary.outPublic.GetName() << endl;
    cout << " Set in handle   " << storagePrimary.handle.GetName() << endl;

    // Export the private key.
    AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA256);
    p.Execute(tpm, s);
    DuplicateResponse dup = tpm(s).Duplicate(storagePrimary.handle, TPM_HANDLE::NullHandle(), NullVec, TPMT_SYM_DEF_OBJECT::NullObject());

    cout << "Duplicated private key:" << dup.ToString(true);

    // Sign using exported key.
    // Import the key into a TSS_KEY. The private key is in a an encoded TPM2B_SENSITIVE.
    TPM2B_SENSITIVE sens;
    sens.FromBuf(dup.duplicate.buffer);

    // And the sensitive area is an RSA key in this case
    TPM2B_PRIVATE_KEY_RSA *rsaPriv = dynamic_cast<TPM2B_PRIVATE_KEY_RSA *>(sens.sensitiveArea.sensitive);

    // Put this in a TSS.C++ defined structure for convenience
    _tssKey = new TSS_KEY(storagePrimary.outPublic, rsaPriv->buffer);

    tpm.FlushContext(s);
    tpm.FlushContext(storagePrimary.handle);
}

char* TpmCppWrapper::GetPrivateKey()
{
    return CryptoServices::ExportPrivateKeyInPEMFormat(_tssKey);
}

char* TpmCppWrapper::GetX509CertCommonName()
{
    // todo: read common name from the certificate.
    return "mydemodevice";
}

char* TpmCppWrapper::_ReadFile()
{
    FILE *file = fopen(_certFilePath.c_str(), "rb");

    if (!file)
    {
        printf("error occurred in fopen");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long fSize = ftell(file);
    rewind(file);

    if(fSize == 0)
    {
        printf("warning: file size is zero");
    }

    char* message = (char*) malloc(fSize);
    if (!message)
    {
        printf("error occurred in malloc");
        return NULL;
    }

    long readCount = fread(message, sizeof(char), fSize, file);

    if (readCount != fSize)
    {
        printf("error occurred in fread");
        return NULL;
    }

    fclose(file);
    return message;
}

char* TpmCppWrapper::GetX509Cert()
{
    char* certificate = NULL;
    certificate = _ReadFile();
    return certificate;
}


int TpmCppWrapper::Createx509SelfSignedCert()
{
    return CryptoServices::Createx509SelfSignedCert(_tssKey, _certFilePath.c_str());
}

TpmCppWrapper::~TpmCppWrapper()
{
    tpm.Shutdown(TPM_SU::CLEAR);
    device.PowerOff();
    device.~TpmTcpDevice();
    return;
}