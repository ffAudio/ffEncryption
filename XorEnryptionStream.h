

#pragma once

/*!
 This class applies an arbitrary secret XORed to the contents of a stream.
 Be aware, that this is not really cryptography but rather obfuscation.
 Use it, if CPU usage matters more than security.
 */
class XorEncryptionStream : public juce::OutputStream
{
public:
    XorEncryptionStream (juce::OutputStream& destStream, std::vector<char> key)
    : output  (destStream),
    secret    (key)
    {
    }

    virtual ~XorEncryptionStream () {}

    void flush () override
    {
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
        juce::MemoryBlock block (dataToWrite, numberOfBytes);

        // apply the secret XORed, make sure to start at the right position in the secret

        return output.write (block.getData(), block.getSize());
    }
private:

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (XorEncryptionStream)

    juce::OutputStream& output;
    std::vector<char>   secret;
};

