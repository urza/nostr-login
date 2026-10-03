using System.Text;
using NostrAuth;

namespace NostrAuth.Tests;

public class ChaCha20Tests
{
    [Fact]
    public void Matches_rfc8439_section_2_4_2()
    {
        var key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = Convert.FromHexString("000000000000004a00000000");
        var plaintext = Encoding.ASCII.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        const string expected =
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";

        var ciphertext = ChaCha20.Process(key, nonce, plaintext, counter: 1);

        Assert.Equal(expected, Convert.ToHexStringLower(ciphertext));
        Assert.Equal(plaintext, ChaCha20.Process(key, nonce, ciphertext, counter: 1));
    }

    [Fact]
    public void Matches_rfc8439_appendix_a2_vector_1()
    {
        // All-zero key and nonce, counter 0: the keystream itself.
        var keystream = ChaCha20.Process(new byte[32], new byte[12], new byte[64]);
        Assert.Equal(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            Convert.ToHexStringLower(keystream));
    }

    [Fact]
    public void Handles_input_that_is_not_a_multiple_of_the_block_size()
    {
        var key = new byte[32];
        var nonce = new byte[12];
        var input = new byte[150];
        var full = ChaCha20.Process(key, nonce, new byte[192]);
        Assert.Equal(full[..150], ChaCha20.Process(key, nonce, input));
    }

    [Fact]
    public void Rejects_wrong_key_or_nonce_length()
    {
        Assert.Throws<ArgumentException>(() => ChaCha20.Process(new byte[31], new byte[12], []));
        Assert.Throws<ArgumentException>(() => ChaCha20.Process(new byte[32], new byte[8], []));
    }
}
