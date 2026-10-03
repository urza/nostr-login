using System.Text;

namespace NostrAuth;

/// <summary>
/// A QR code encoder (ISO/IEC 18004, model 2) for the Nostr Connect URI on the login page.
/// Byte mode only, versions 1 to 40, all four error correction levels. About 300 lines replace
/// a package that pulled in System.Drawing. The structure follows the public-domain reference
/// design by Project Nayuki: build the data codewords, add Reed-Solomon blocks, draw the function
/// patterns, place the data in the zigzag order, then pick the mask with the lowest penalty.
/// </summary>
internal sealed class QrCode
{
    public enum Ecc { L = 1, M = 0, Q = 3, H = 2 } // The values are the format-bit codes.

    public int Version { get; }
    public int Size { get; }
    public Ecc Level { get; }
    public int Mask { get; private set; }

    private readonly bool[,] _modules;    // [y, x], true = dark
    private readonly bool[,] _isFunction; // modules that carry no data and no mask

    public bool this[int x, int y] => _modules[y, x];

    /// <summary>Encodes UTF-8 text at the smallest version that fits.</summary>
    public static QrCode Encode(string text, Ecc level = Ecc.L)
    {
        var data = Encoding.UTF8.GetBytes(text);
        for (var version = 1; version <= 40; version++)
        {
            var capacityBits = DataCodewords(version, level) * 8;
            var neededBits = 4 + CharCountBits(version) + data.Length * 8;
            if (neededBits <= capacityBits) return new QrCode(version, level, data);
        }
        throw new ArgumentException("Text is too long for a QR code.", nameof(text));
    }

    /// <summary>Renders the code as an SVG with a quiet zone, for inline use on a web page.</summary>
    public string ToSvg(int quietZone = 4, int pixelsPerModule = 4)
    {
        var total = Size + 2 * quietZone;
        var path = new StringBuilder();
        for (var y = 0; y < Size; y++)
        {
            for (var x = 0; x < Size; x++)
            {
                if (!_modules[y, x]) continue;
                var run = 1;
                while (x + run < Size && _modules[y, x + run]) run++;
                path.Append('M').Append(x + quietZone).Append(' ').Append(y + quietZone).Append('h').Append(run).Append("v1h-").Append(run).Append('z');
                x += run - 1;
            }
        }
        var px = total * pixelsPerModule;
        return $"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{px}\" height=\"{px}\" viewBox=\"0 0 {total} {total}\" shape-rendering=\"crispEdges\">"
             + "<rect width=\"100%\" height=\"100%\" fill=\"#fff\"/>"
             + $"<path fill=\"#000\" d=\"{path}\"/></svg>";
    }

    private QrCode(int version, Ecc level, byte[] data)
    {
        Version = version;
        Level = level;
        Size = version * 4 + 17;
        _modules = new bool[Size, Size];
        _isFunction = new bool[Size, Size];

        DrawFunctionPatterns();
        PlaceData(AddEccAndInterleave(BuildDataCodewords(data)));
        ChooseMask();
    }

    // ---- Data codewords ------------------------------------------------------------------

    private byte[] BuildDataCodewords(byte[] data)
    {
        var bits = new BitWriter();
        bits.Write(0b0100, 4); // byte mode
        bits.Write(data.Length, CharCountBits(Version));
        foreach (var b in data) bits.Write(b, 8);

        var capacity = DataCodewords(Version, Level) * 8;
        bits.Write(0, Math.Min(4, capacity - bits.Length)); // terminator
        bits.Write(0, (8 - bits.Length % 8) % 8);           // to a byte boundary
        for (var pad = 0xEC; bits.Length < capacity; pad ^= 0xEC ^ 0x11) bits.Write(pad, 8);
        return bits.ToArray();
    }

    private static int CharCountBits(int version) => version < 10 ? 8 : 16;

    private sealed class BitWriter
    {
        private readonly List<byte> _bytes = [];
        public int Length { get; private set; }

        public void Write(int value, int count)
        {
            for (var i = count - 1; i >= 0; i--, Length++)
            {
                if (Length % 8 == 0) _bytes.Add(0);
                if (((value >> i) & 1) != 0) _bytes[^1] |= (byte)(0x80 >> (Length % 8));
            }
        }

        public byte[] ToArray() => [.. _bytes];
    }

    // ---- Error correction ----------------------------------------------------------------

    private byte[] AddEccAndInterleave(byte[] data)
    {
        var numBlocks = EccBlocks[(int)Level, Version];
        var eccLen = EccCodewordsPerBlock[(int)Level, Version];
        var rawCodewords = RawDataModules(Version) / 8;
        var numShortBlocks = numBlocks - rawCodewords % numBlocks;
        var shortBlockLen = rawCodewords / numBlocks;

        var divisor = RsDivisor(eccLen);
        var blocks = new byte[numBlocks][];
        for (int i = 0, k = 0; i < numBlocks; i++)
        {
            var dataLen = shortBlockLen - eccLen + (i < numShortBlocks ? 0 : 1);
            var block = new byte[shortBlockLen + 1];
            data.AsSpan(k, dataLen).CopyTo(block);
            RsRemainder(data.AsSpan(k, dataLen), divisor).CopyTo(block.AsSpan(block.Length - eccLen));
            k += dataLen;
            blocks[i] = block;
        }

        // Interleave: codeword i of every block in turn. Short blocks have no codeword at the
        // padding index, which sits right before their ECC part.
        var result = new byte[rawCodewords];
        for (int i = 0, k = 0; i < blocks[0].Length; i++)
            for (var j = 0; j < numBlocks; j++)
                if (i != shortBlockLen - eccLen || j >= numShortBlocks) result[k++] = blocks[j][i];
        return result;
    }

    /// <summary>Generator polynomial (x - 2^0)(x - 2^1)...(x - 2^(degree-1)) over GF(2^8), without the leading 1.</summary>
    internal static byte[] RsDivisor(int degree)
    {
        var result = new byte[degree];
        result[^1] = 1;
        var root = 1;
        for (var i = 0; i < degree; i++)
        {
            for (var j = 0; j < degree; j++)
            {
                result[j] = GfMultiply(result[j], root);
                if (j + 1 < degree) result[j] ^= result[j + 1];
            }
            root = GfMultiply(root, 2);
        }
        return result;
    }

    /// <summary>Polynomial division remainder: the error correction codewords for <paramref name="data"/>.</summary>
    internal static byte[] RsRemainder(ReadOnlySpan<byte> data, byte[] divisor)
    {
        var result = new byte[divisor.Length];
        foreach (var b in data)
        {
            var factor = b ^ result[0];
            result.AsSpan(1).CopyTo(result);
            result[^1] = 0;
            for (var i = 0; i < divisor.Length; i++) result[i] ^= GfMultiply(divisor[i], factor);
        }
        return result;
    }

    private static byte GfMultiply(int x, int y)
    {
        var z = 0;
        for (var i = 7; i >= 0; i--)
        {
            z = (z << 1) ^ ((z >> 7) * 0x11D); // the QR code field polynomial x^8 + x^4 + x^3 + x^2 + 1
            z ^= ((y >> i) & 1) * x;
        }
        return (byte)z;
    }

    // ---- Function patterns ---------------------------------------------------------------

    private void DrawFunctionPatterns()
    {
        for (var i = 0; i < Size; i++)
        {
            SetFunction(6, i, i % 2 == 0); // timing patterns
            SetFunction(i, 6, i % 2 == 0);
        }
        DrawFinder(3, 3);
        DrawFinder(Size - 4, 3);
        DrawFinder(3, Size - 4);

        var align = AlignmentPositions(Version);
        for (var i = 0; i < align.Length; i++)
            for (var j = 0; j < align.Length; j++)
            {
                var corner = (i == 0 && j == 0) || (i == 0 && j == align.Length - 1) || (i == align.Length - 1 && j == 0);
                if (!corner) DrawAlignment(align[i], align[j]);
            }

        DrawFormatBits(0); // reserves the modules; the real mask is written in ChooseMask
        DrawVersion();
    }

    private void DrawFinder(int x, int y)
    {
        for (var dy = -4; dy <= 4; dy++)
            for (var dx = -4; dx <= 4; dx++)
            {
                var dist = Math.Max(Math.Abs(dx), Math.Abs(dy));
                int xx = x + dx, yy = y + dy;
                if (xx >= 0 && xx < Size && yy >= 0 && yy < Size) SetFunction(xx, yy, dist != 2 && dist != 4);
            }
    }

    private void DrawAlignment(int x, int y)
    {
        for (var dy = -2; dy <= 2; dy++)
            for (var dx = -2; dx <= 2; dx++)
                SetFunction(x + dx, y + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
    }

    private void DrawFormatBits(int mask)
    {
        var data = ((int)Level << 3) | mask;
        var rem = data;
        for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        var bits = ((data << 10) | rem) ^ 0x5412;

        bool Bit(int i) => ((bits >> i) & 1) != 0;

        // First copy, around the top-left finder.
        for (var i = 0; i <= 5; i++) SetFunction(8, i, Bit(i));
        SetFunction(8, 7, Bit(6));
        SetFunction(8, 8, Bit(7));
        SetFunction(7, 8, Bit(8));
        for (var i = 9; i < 15; i++) SetFunction(14 - i, 8, Bit(i));

        // Second copy, split between the other two finders.
        for (var i = 0; i < 8; i++) SetFunction(Size - 1 - i, 8, Bit(i));
        for (var i = 8; i < 15; i++) SetFunction(8, Size - 15 + i, Bit(i));
        SetFunction(8, Size - 8, true); // always dark
    }

    private void DrawVersion()
    {
        if (Version < 7) return;
        var rem = Version;
        for (var i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        var bits = (Version << 12) | rem;
        for (var i = 0; i < 18; i++)
        {
            var bit = ((bits >> i) & 1) != 0;
            int a = Size - 11 + i % 3, b = i / 3;
            SetFunction(a, b, bit);
            SetFunction(b, a, bit);
        }
    }

    private void SetFunction(int x, int y, bool dark)
    {
        _modules[y, x] = dark;
        _isFunction[y, x] = true;
    }

    // ---- Data placement and masking ------------------------------------------------------

    private void PlaceData(byte[] codewords)
    {
        var i = 0;
        for (var right = Size - 1; right >= 1; right -= 2)
        {
            if (right == 6) right = 5; // skip the vertical timing pattern
            for (var vert = 0; vert < Size; vert++)
                for (var j = 0; j < 2; j++)
                {
                    var x = right - j;
                    var upward = ((right + 1) & 2) == 0;
                    var y = upward ? Size - 1 - vert : vert;
                    if (_isFunction[y, x] || i >= codewords.Length * 8) continue;
                    _modules[y, x] = ((codewords[i >> 3] >> (7 - (i & 7))) & 1) != 0;
                    i++;
                }
        }
        // Remainder bits (0 to 7) stay light.
    }

    private void ChooseMask()
    {
        int best = -1, bestPenalty = int.MaxValue;
        for (var mask = 0; mask < 8; mask++)
        {
            ApplyMask(mask);
            DrawFormatBits(mask);
            var penalty = Penalty();
            if (penalty < bestPenalty) (best, bestPenalty) = (mask, penalty);
            ApplyMask(mask); // XOR again to undo
        }
        ApplyMask(best);
        DrawFormatBits(best);
        Mask = best;
    }

    private void ApplyMask(int mask)
    {
        for (var y = 0; y < Size; y++)
            for (var x = 0; x < Size; x++)
            {
                if (_isFunction[y, x]) continue;
                var invert = mask switch
                {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                _modules[y, x] ^= invert;
            }
    }

    /// <summary>The four penalty rules of the standard. A lower score reads better; any mask is still valid.</summary>
    private int Penalty()
    {
        var penalty = 0;
        var line = new bool[Size];

        for (var pass = 0; pass < 2; pass++) // rows, then columns
            for (var a = 0; a < Size; a++)
            {
                for (var b = 0; b < Size; b++) line[b] = pass == 0 ? _modules[a, b] : _modules[b, a];

                // Rule 1: runs of 5 or more same-colored modules.
                for (var b = 0; b < Size;)
                {
                    var run = 1;
                    while (b + run < Size && line[b + run] == line[b]) run++;
                    if (run >= 5) penalty += run - 2;
                    b += run;
                }

                // Rule 3: finder-like 1:1:3:1:1 pattern with 4 light modules on one side.
                for (var b = 0; b + 11 <= Size; b++)
                {
                    var core = line[b] && !line[b + 1] && line[b + 2] && line[b + 3] && line[b + 4] && !line[b + 5] && line[b + 6];
                    var coreShifted = line[b + 4] && !line[b + 5] && line[b + 6] && line[b + 7] && line[b + 8] && !line[b + 9] && line[b + 10];
                    var lightBefore = !line[b] && !line[b + 1] && !line[b + 2] && !line[b + 3];
                    var lightAfter = !line[b + 7] && !line[b + 8] && !line[b + 9] && !line[b + 10];
                    if ((core && lightAfter) || (lightBefore && coreShifted)) penalty += 40;
                }
            }

        // Rule 2: 2x2 blocks of one color.
        for (var y = 0; y + 1 < Size; y++)
            for (var x = 0; x + 1 < Size; x++)
            {
                var c = _modules[y, x];
                if (c == _modules[y, x + 1] && c == _modules[y + 1, x] && c == _modules[y + 1, x + 1]) penalty += 3;
            }

        // Rule 4: dark modules far from 50 %.
        var dark = 0;
        foreach (var m in _modules) if (m) dark++;
        var percent = dark * 100 / (Size * Size);
        var k = Math.Min(Math.Abs(percent / 5 * 5 - 50), Math.Abs((percent / 5 + 1) * 5 - 50)) / 5;
        return penalty + k * 10;
    }

    // ---- Tables --------------------------------------------------------------------------

    internal static int DataCodewords(int version, Ecc level) =>
        RawDataModules(version) / 8 - EccCodewordsPerBlock[(int)level, version] * EccBlocks[(int)level, version];

    /// <summary>Modules left for codewords after the function patterns, including remainder bits.</summary>
    private static int RawDataModules(int version)
    {
        var result = (16 * version + 128) * version + 64;
        if (version >= 2)
        {
            var numAlign = version / 7 + 2;
            result -= (25 * numAlign - 10) * numAlign - 55;
            if (version >= 7) result -= 36;
        }
        return result;
    }

    internal static int[] AlignmentPositions(int version)
    {
        if (version == 1) return [];
        var numAlign = version / 7 + 2;
        var size = version * 4 + 17;
        var step = version == 32 ? 26 : (version * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2) * 2;
        var result = new int[numAlign];
        result[0] = 6;
        for (int i = numAlign - 1, pos = size - 7; i >= 1; i--, pos -= step) result[i] = pos;
        return result;
    }

    // Indexed [level, version]. Row order follows the Ecc enum values: M = 0, L = 1, H = 2, Q = 3.
    private static readonly byte[,] EccCodewordsPerBlock =
    {
        { 0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28 }, // M
        { 0,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 }, // L
        { 0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 }, // H
        { 0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 }, // Q
    };

    private static readonly byte[,] EccBlocks =
    {
        { 0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5,  8,  9,  9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49 }, // M
        { 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4,  4,  4,  4,  6,  6,  6,  6,  7,  8,  8,  9,  9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25 }, // L
        { 0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81 }, // H
        { 0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8,  10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68 }, // Q
    };
}
