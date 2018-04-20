

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
        jassert (output.getPosition() % blockSize == padded);

        juce::BigInteger block;
        block.loadFromMemoryBlock (blockToEncrypt);
        rsaKey.applyToValue (block);
        auto encodedBlock = block.toMemoryBlock();
        auto* ptr = (char*)encodedBlock.getData();
        ptr += padded;
        output.write (ptr, encodedBlock.getSize() - padded);

        blockToEncrypt.reset();
        padded = output.getPosition() % blockSize;
    }

    bool setPosition (juce::int64 newPosition) override
    {
        flush();
        padded = newPosition % blockSize;
        blockToEncrypt.setSize (padded, true);
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
    int                 padded = 0;
};

