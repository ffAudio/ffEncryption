

#pragma once

class RSAEncryptionStream : public juce::OutputStream
{
public:
    RSAEncryptionStream (juce::OutputStream& destStream, juce::RSAKey& key, const int keySize = 4096)
    : output  (destStream),
    rsaKey    (key),
    blockSize (keySize)
    {

    }

    void flush () override
    {
        jassert (output.getPosition() % blockSize == 0);

        juce::BigInteger block;
        block.loadFromMemoryBlock (blockToEncrypt);
        rsaKey.applyToValue (block);
        auto encodedBlock = block.toMemoryBlock();
        output.write (encodedBlock.getData(), encodedBlock.getSize());

        blockToEncrypt.reset();
    }

    bool setPosition (juce::int64 newPosition) override
    {
        flush();
        return output.setPosition (newPosition);
    }

    juce::int64 getPosition () override
    {
        return output.getPosition();
    }

    bool write (const void *dataToWrite, size_t numberOfBytes) override
    {
        auto  bytesToWrite = numberOfBytes;
        auto* nextBytesPtr = (uint8_t*)dataToWrite;

        while (bytesToWrite > 0) {
            auto nextBytes = std::min (blockSize - blockToEncrypt.getSize(), bytesToWrite);
            blockToEncrypt.append (nextBytesPtr, nextBytes);

            bytesToWrite -= nextBytes;
            nextBytesPtr += nextBytes;
            if (blockToEncrypt.getSize() == blockSize)
                flush();
        }

        return true;
    }
private:

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (RSAEncryptionStream)

    juce::OutputStream& output;
    juce::RSAKey        rsaKey;
    int                 blockSize;
    juce::MemoryBlock   blockToEncrypt;
};

