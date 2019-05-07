
using namespace TpmCpp;

class TpmCppWrapper
{
public:
    TpmCppWrapper(const string &certFilePath);
    ~TpmCppWrapper();
    char* GetPrivateKey();
    char* GetX509Cert();
    char* GetX509CertCommonName();
    int Createx509SelfSignedCert();

private:
    char* _ReadFile();
    TSS_KEY* _tssKey;
    TpmCpp::Tpm2 tpm;
    TpmCpp::TpmTcpDevice device;
    string _certFilePath;
    void _DeriveRsaKeyFromTpm();
};