
#pragma once

/*!
 This class applies an arbitrary secret XORed to the contents of a stream.
 Be aware, that this is not really cryptography but rather obfuscation.
 Use it, if CPU usage matters more than security.
 */
class XorDecryptionStream : public juce::InputStream
{
public:
    XorDecryptionStream (juce::InputStream& readStream, const std::vector<char> key)
    : input   (readStream),
    secret    (key)
    {
        jassert (key.size() > 0);
    }

    virtual ~XorDecryptionStream () {}

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
        juce::MemoryBlock block (maxBytesToRead);
        auto readBytes = input.read (block.getData(), maxBytesToRead);
        // apply the secret XORed, make sure to start at the right position in the secret
        auto keyPos = input.getPosition() % secret.size();

        auto* ptr   = (char*)destBuffer;
        for (int i=0; i < block.getSize(); ++i) {
            *ptr ^= secret [keyPos];
            ++ptr;
            if (++keyPos >= secret.size()) {
                keyPos = 0;
            }
        }

        return readBytes;
    }

    juce::int64 getPosition () override
    {
        return input.getPosition();
    }

    bool setPosition (juce::int64 newPosition) override
    {
        return input.setPosition (newPosition);
    }

private:

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (XorDecryptionStream)

    juce::InputStream& input;
    std::vector<char>  secret;
};
