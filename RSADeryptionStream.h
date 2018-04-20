
#pragma once

class RSADecryptionStream : public juce::InputStream
{
public:
    RSADecryptionStream (juce::InputStream& readStream, juce::RSAKey& key, const int keySize = 4096)
    : input   (readStream),
    rsaKey    (key),
    blockSize (keySize)
    {
    }

    juce::int64 getTotalLength () override
    {
        return input.getTotalLength();
    }

    bool isExhausted () override
    {
        return position >= input.getTotalLength();
    }

    int read (void *destBuffer, int maxBytesToRead) override
    {
        auto* writePos = (char*)destBuffer;
        auto  pos = 0;
        auto  bytesNeeded = maxBytesToRead;
        while (bytesNeeded > 0) {
            if (position < decodedPosition ||
                position >= decodedPosition + decodedBlock.getSize()) {
                decodedPosition = position -  position % blockSize;
                decodedBlock.setSize (blockSize);
                input.setPosition (decodedPosition);
                auto readBytes = input.read (decodedBlock.getData(), decodedBlock.getSize());
                decodedBlock.setSize (readBytes);
                juce::BigInteger crypted;
                crypted.loadFromMemoryBlock (decodedBlock);
                rsaKey.applyToValue (crypted);
                decodedBlock = crypted.toMemoryBlock();
            }

            auto localPos = position - decodedPosition;
            auto bytesToCopy = std::min ((int)(decodedBlock.getSize() - localPos), bytesNeeded);
            memcpy (writePos, (char*)decodedBlock.getData() + localPos, bytesToCopy);
            writePos    += bytesToCopy;
            bytesNeeded -= bytesToCopy;
            position    += bytesToCopy;
        }

        return maxBytesToRead;
    }

    juce::int64 getPosition () override
    {
        return position;
    }

    bool setPosition (juce::int64 newPosition) override
    {
        if (newPosition < input.getTotalLength()) {
            position = newPosition;
            return true;
        }

        position = input.getTotalLength();
        return false;
    }

private:

    void decryptBlock (juce::int64 position);


    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (RSADecryptionStream)

    juce::InputStream& input;
    juce::RSAKey       rsaKey;
    int                blockSize;
    juce::int64        position = 0;
    juce::int64        decodedPosition = -1;
    juce::MemoryBlock  decodedBlock;
};
