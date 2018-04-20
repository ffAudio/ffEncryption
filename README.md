# ffEncryption

This module adds an encrypt and decrypt stream to intercept any kind of reading.

Note: *RSAEncryptionStream is work in progress, it doesn't work yet*

Here is the test program:

```
#include "../JuceLibraryCode/JuceHeader.h"

//==============================================================================
int main (int argc, char* argv[])
{
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

            while (!input.isExhausted()) {
                encryptStream.writeByte (input.readByte());
            }
        }

        {
            FileInputStream input (outFile);
            FFAU::RSADecryptionStream decryptStream (input, publicKey, keySize / 8);

            FileOutputStream output (checkFile);

            while (!decryptStream.isExhausted()) {
                output.writeByte (decryptStream.readByte());
            }
        }
    }

    {
        std::vector<char> secret (1024);
        Random::getSystemRandom().fillBitsRandomly (secret.data(), 1024);

        auto inFile     = File::getSpecialLocation (File::userHomeDirectory).getChildFile ("testfile.txt");
        auto outFile    = File::getSpecialLocation (File::userHomeDirectory).getChildFile ("testfile.xor");
        auto checkFile  = File::getSpecialLocation (File::userHomeDirectory).getChildFile ("testfile.xorcheck");

        outFile.deleteFile();
        checkFile.deleteFile();

        {
            FileOutputStream output (outFile);
            FFAU::XorEncryptionStream encryptStream (output, secret);

            FileInputStream input (inFile);

            while (!input.isExhausted()) {
                encryptStream.writeByte (input.readByte());
            }
        }

        {
            FileInputStream input (outFile);
            FFAU::XorDecryptionStream decryptStream (input, secret);

            FileOutputStream output (checkFile);

            while (!decryptStream.isExhausted()) {
                output.writeByte (decryptStream.readByte());
            }
        }

    }
    return 0;
}
```

