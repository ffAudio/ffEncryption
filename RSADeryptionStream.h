
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
        return input.isExhausted();
    }

    int read (void *destBuffer, int maxBytesToRead) override
    {
        // TODO: read and decrypt


        return input.read (destBuffer, maxBytesToRead);
    }

    juce::int64 getPosition () override
    {
        return input.getPosition();
    }

    bool setPosition (juce::int64 newPosition) override
    {
        decodedPosition = -1;
        return input.setPosition (newPosition);
    }

private:

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (RSADecryptionStream)

    juce::InputStream& input;
    juce::RSAKey       rsaKey;
    int                blockSize;
    juce::int64        decodedPosition = -1;
    juce::MemoryBlock  decodedBlock;
};
