# ffEncryption

This module adds an encrypt and decrypt stream to intercept any kind of reading.
Here is the test program:

```
#include "../JuceLibraryCode/JuceHeader.h"

//==============================================================================
int main (int argc, char* argv[])
{
    int keySize = 256;
    RSAKey publicKey, privateKey;
    RSAKey::createKeyPair (publicKey, privateKey, keySize);

    auto inFile     = File::getSpecialLocation (File::userHomeDirectory).getChildFile ("testfile.txt");
    auto outFile    = File::getSpecialLocation (File::userHomeDirectory).getChildFile ("testfile.crypt");
    auto checkFile  = File::getSpecialLocation (File::userHomeDirectory).getChildFile ("testfile.check");

    outFile.deleteFile();
    checkFile.deleteFile();

    {
        FileOutputStream output (outFile);
        FFAU::RSAEncryptionStream encryptStream (output, privateKey, keySize / 8);

        FileInputStream input (inFile);

        while (!input.isExhausted())
            encryptStream.writeByte (input.readByte());
    }

    {
        FileInputStream input (outFile);
        FFAU::RSADecryptionStream decryptStream (input, publicKey, keySize / 8);

        FileOutputStream output (checkFile);

        while (!decryptStream.isExhausted())
            output.writeByte (decryptStream.readByte());
    }

    return 0;
}
```

