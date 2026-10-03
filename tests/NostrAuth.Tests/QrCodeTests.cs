using System.Text;
using NostrAuth;
using ZXing;
using ZXing.Common;

namespace NostrAuth.Tests;

public class QrCodeTests
{
    private const string ConnectUri =
        "nostrconnect://3f1d9b9a5c4e2f7a8b6d0c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2?relay=wss%3A%2F%2Frelay.primal.net" +
        "&relay=wss%3A%2F%2Fnrs.primal.net&relay=wss%3A%2F%2Frelay.nip46.com&relay=wss%3A%2F%2Fbucket.coracle.social" +
        "&secret=0f1e2d3c4b5a69788796a5b4c3d2e1f0&perms=sign_event%3A27235&name=Nostr%20Guestbook&url=https%3A%2F%2Furza.cc";

    [Theory]
    [InlineData("A")]
    [InlineData("HELLO WORLD")]
    [InlineData("https://example.com/signin-nostr?state=abc")]
    [InlineData(ConnectUri)]
    public void Independent_reader_decodes_the_code(string text)
    {
        foreach (var level in new[] { QrCode.Ecc.L, QrCode.Ecc.M, QrCode.Ecc.Q, QrCode.Ecc.H })
        {
            var qr = QrCode.Encode(text, level);
            Assert.Equal(text, Decode(qr));
        }
    }

    [Fact]
    public void Every_version_decodes()
    {
        // Fill each version to its byte-mode capacity at level L, so the test covers all 40 layouts,
        // both character-count widths, and the version information area (7 and up).
        for (var version = 1; version <= 40; version++)
        {
            var capacity = (QrCode.DataCodewords(version, QrCode.Ecc.L) * 8 - 4 - (version < 10 ? 8 : 16)) / 8;
            var text = Fill(capacity, version);
            var qr = QrCode.Encode(text);
            Assert.Equal(version, qr.Version);
            Assert.Equal(text, Decode(qr));
        }
    }

    [Fact]
    public void Picks_the_smallest_version_that_fits()
    {
        Assert.Equal(1, QrCode.Encode(Fill(17, 1)).Version);  // 17 bytes is the byte-mode limit of 1-L
        Assert.Equal(2, QrCode.Encode(Fill(18, 2)).Version);
        Assert.Throws<ArgumentException>(() => QrCode.Encode(Fill(2954, 0))); // 40-L holds 2953
    }

    [Fact]
    public void Reed_solomon_matches_the_textbook_example()
    {
        // The "HELLO WORLD" 1-M example: 16 data codewords and their 10 error correction codewords.
        byte[] data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
        byte[] expected = [196, 35, 39, 119, 235, 215, 231, 226, 93, 23];
        Assert.Equal(expected, QrCode.RsRemainder(data, QrCode.RsDivisor(10)));
    }

    [Fact]
    public void Alignment_positions_match_the_standard()
    {
        Assert.Empty(QrCode.AlignmentPositions(1));
        Assert.Equal([6, 18], QrCode.AlignmentPositions(2));
        Assert.Equal([6, 22, 38], QrCode.AlignmentPositions(7));
        Assert.Equal([6, 26, 46, 66], QrCode.AlignmentPositions(14));
        Assert.Equal([6, 34, 60, 86, 112, 138], QrCode.AlignmentPositions(32));
        Assert.Equal([6, 30, 58, 86, 114, 142, 170], QrCode.AlignmentPositions(40));
    }

    [Fact]
    public void Svg_has_a_quiet_zone_and_no_markup_from_the_text()
    {
        var svg = QrCode.Encode("<script>alert(1)</script>").ToSvg();
        Assert.StartsWith("<svg xmlns=\"http://www.w3.org/2000/svg\"", svg);
        Assert.DoesNotContain("script", svg);
        var size = QrCode.Encode("<script>alert(1)</script>").Size + 8;
        Assert.Contains($"viewBox=\"0 0 {size} {size}\"", svg);
    }

    private static string Fill(int bytes, int seed)
    {
        var sb = new StringBuilder(bytes);
        var rng = new Random(seed);
        while (sb.Length < bytes) sb.Append((char)('!' + rng.Next(94))); // printable ASCII, one byte each
        return sb.ToString();
    }

    private static string Decode(QrCode qr)
    {
        // Render each module as a 3x3 block with a 4-module quiet zone, as a reader sees it on a screen.
        const int scale = 3, quiet = 4;
        var width = (qr.Size + 2 * quiet) * scale;
        var pixels = new byte[width * width * 3];
        Array.Fill(pixels, (byte)255);
        for (var y = 0; y < qr.Size; y++)
            for (var x = 0; x < qr.Size; x++)
            {
                if (!qr[x, y]) continue;
                for (var dy = 0; dy < scale; dy++)
                    for (var dx = 0; dx < scale; dx++)
                    {
                        var i = (((y + quiet) * scale + dy) * width + (x + quiet) * scale + dx) * 3;
                        pixels[i] = pixels[i + 1] = pixels[i + 2] = 0;
                    }
            }

        // PureBarcode: the image is only the code. Without it, ZXing's finder search gives up on some
        // dense codes (version 28 with random content), while the same code decodes in pure mode.
        var reader = new BarcodeReaderGeneric
        {
            Options = new DecodingOptions { PossibleFormats = [BarcodeFormat.QR_CODE], PureBarcode = true, CharacterSet = "UTF-8" },
        };
        var result = reader.Decode(new RGBLuminanceSource(pixels, width, width, RGBLuminanceSource.BitmapFormat.RGB24));
        Assert.NotNull(result);
        return result.Text;
    }
}
