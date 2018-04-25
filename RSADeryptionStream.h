
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
        int bytesProduced = 0;
        auto* writePos = (char*)destBuffer;
        auto  bytesNeeded = maxBytesToRead;
        while (!isExhausted() && bytesNeeded > 0) {
            if (decodedBlock.getSize() <= 0 ||
                position < decodedBlockPosition ||
                position >= decodedBlockPosition + decodedBlock.getSize())
            {
                decodedBlockPosition = blockSize * (position / blockSize);
//                DBG ("Decrypt: " << decodedBlockPosition << " (for: " << position << ")");
                decodedBlock.setSize (blockSize);
                input.setPosition (decodedBlockPosition);
                auto readBytes = input.read (decodedBlock.getData(), decodedBlock.getSize());
                decodedBlock.setSize (readBytes);
                juce::BigInteger crypted;
                crypted.loadFromMemoryBlock (decodedBlock);
                rsaKey.applyToValue (crypted);
                decodedBlock = crypted.toMemoryBlock();
            }

            auto localPos = position - decodedBlockPosition;
            auto bytesToCopy = std::min ((int)(decodedBlock.getSize() - localPos), bytesNeeded);
            jassert (juce::isPositiveAndBelow (bytesToCopy, maxBytesToRead+1));
            memcpy (writePos, (char*)decodedBlock.getData() + localPos, bytesToCopy);
            writePos      += bytesToCopy;
            bytesNeeded   -= bytesToCopy;
            position      += bytesToCopy;
            bytesProduced += bytesToCopy;
            jassert (bytesProduced > 0);
        }

        return bytesProduced;
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
    juce::int64        decodedBlockPosition = -1;
    juce::MemoryBlock  decodedBlock;
};
