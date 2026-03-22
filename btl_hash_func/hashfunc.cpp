#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <fstream>

using namespace std;

using u8  = uint8_t;
using u64 = uint64_t;

// ========================= HANG SO SHA-512 =========================
static const array<u64, 80> K = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const array<u64, 8> H0 = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL
};

// ========================= CAC HAM HO TRO =========================
u64 rotr(u64 x, int n) {
    return (x >> n) | (x << (64 - n));
}

u64 shr(u64 x, int n) {
    return x >> n;
}

u64 Ch(u64 x, u64 y, u64 z) {
    return (x & y) ^ (~x & z);
}

u64 Maj(u64 x, u64 y, u64 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

u64 BSIG0(u64 x) {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

u64 BSIG1(u64 x) {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

u64 SSIG0(u64 x) {
    return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7);
}

u64 SSIG1(u64 x) {
    return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6);
}

string hex64(u64 x) {
    stringstream ss;
    ss << hex << nouppercase << setfill('0') << setw(16) << x;
    return ss.str();
}

void print_bytes_hex(const vector<u8>& data, ostream& out, size_t perLine = 16) {
    for (size_t i = 0; i < data.size(); ++i) {
        out << hex << nouppercase << setfill('0') << setw(2)
            << static_cast<unsigned>(data[i]) << " ";
        if ((i + 1) % perLine == 0) out << "\n";
    }
    if (data.size() % perLine != 0) out << "\n";
    out << dec;
}

// ========================= TIEN XU LY / PADDING =========================
vector<u8> preprocessSHA512(const string& msg, ostream& logFile, bool logPadding) {
    vector<u8> data(msg.begin(), msg.end());

    u64 bit_len_high = 0;
    u64 bit_len_low  = static_cast<u64>(data.size()) * 8ULL;

    if (logPadding) {
        logFile << "========== [1] INPUT ==========\n";
        logFile << "Chuoi goc: \"" << msg << "\"\n";
        logFile << "So byte ban dau: " << data.size() << "\n";
        logFile << "Do dai bit ban dau: " << bit_len_low << "\n\n";
    }

    data.push_back(0x80);

    while ((data.size() + 16) % 128 != 0) {
        data.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        data.push_back(static_cast<u8>((bit_len_high >> (i * 8)) & 0xFF));
    }
    for (int i = 7; i >= 0; --i) {
        data.push_back(static_cast<u8>((bit_len_low >> (i * 8)) & 0xFF));
    }

    if (logPadding) {
        logFile << "========== [2] SAU PADDING ==========\n";
        logFile << "Tong so byte sau padding: " << data.size() << "\n";
        logFile << "So block 1024-bit: " << data.size() / 128 << "\n";
        logFile << "Du lieu sau padding (hex):\n";
        print_bytes_hex(data, logFile);
        logFile << "\n";
    }

    return data;
}

// ========================= SHA-512 GHI LOG RA FILE =========================
string sha512_trace_to_file(const string& msg,
                            ostream& logFile,
                            bool logPadding = true,
                            bool logSchedule = true,
                            bool logRounds = true,
                            bool logHEachBlock = true) {
    vector<u8> data = preprocessSHA512(msg, logFile, logPadding);
    array<u64, 8> H = H0;

    size_t numBlocks = data.size() / 128;

    for (size_t blockIndex = 0; blockIndex < numBlocks; ++blockIndex) {
        logFile << "========================================\n";
        logFile << "BLOCK " << blockIndex << "\n";
        logFile << "========================================\n";

        array<u64, 80> W{};
        size_t offset = blockIndex * 128; // so byte offset cua block hien tai trong data

        for (int t = 0; t < 16; ++t) {
            u64 word = 0;
            for (int j = 0; j < 8; ++j) {
                word = (word << 8) | data[offset + t * 8 + j];
            }
            W[t] = word;
        }
        
        logFile << "[3] 16 WORD DAU TU BLOCK:\n";
        for (int t = 0; t < 16; ++t) {
            logFile << "W[" << setw(2) << setfill('0') << t << "] = 0x" << hex64(W[t]) << "\n";
        }
        logFile << "\n";

        for (int t = 16; t < 80; ++t) {
            W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
        }

        if (logSchedule) {
            logFile << "[4] MESSAGE SCHEDULE W[16..79]:\n";
            for (int t = 16; t < 80; ++t) {
                logFile << "W[" << setw(2) << setfill('0') << t << "] = 0x" << hex64(W[t]) << "\n";
            }
            logFile << "\n";
        }

        u64 a = H[0], b = H[1], c = H[2], d = H[3];
        u64 e = H[4], f = H[5], g = H[6], h = H[7];

        logFile << "[5] GIA TRI KHOI TAO a..h TRUOC 80 ROUND:\n";
        logFile << "a = " << hex64(a) << "\n";
        logFile << "b = " << hex64(b) << "\n";
        logFile << "c = " << hex64(c) << "\n";
        logFile << "d = " << hex64(d) << "\n";
        logFile << "e = " << hex64(e) << "\n";
        logFile << "f = " << hex64(f) << "\n";
        logFile << "g = " << hex64(g) << "\n";
        logFile << "h = " << hex64(h) << "\n\n";

        for (int t = 0; t < 80; ++t) {
            u64 T1 = h + BSIG1(e) + Ch(e, f, g) + K[t] + W[t];
            u64 T2 = BSIG0(a) + Maj(a, b, c);

            if (logRounds) {
                logFile << "----- ROUND " << setw(2) << setfill('0') << t << " -----\n";
                logFile << "W[" << t << "] = " << hex64(W[t]) << "\n";
                logFile << "K[" << t << "] = " << hex64(K[t]) << "\n";
                logFile << "T1 = " << hex64(T1) << "\n";
                logFile << "T2 = " << hex64(T2) << "\n";

                logFile << "Before:\n";
                logFile << "a=" << hex64(a) << " b=" << hex64(b)
                        << " c=" << hex64(c) << " d=" << hex64(d) << "\n";
                logFile << "e=" << hex64(e) << " f=" << hex64(f)
                        << " g=" << hex64(g) << " h=" << hex64(h) << "\n";
            }

            u64 new_a = T1 + T2;
            u64 new_e = d + T1;

            h = g;
            g = f;
            f = e;
            e = new_e;
            d = c;
            c = b;
            b = a;
            a = new_a;

            if (logRounds) {
                logFile << "After:\n";
                logFile << "a=" << hex64(a) << " b=" << hex64(b)
                        << " c=" << hex64(c) << " d=" << hex64(d) << "\n";
                logFile << "e=" << hex64(e) << " f=" << hex64(f)
                        << " g=" << hex64(g) << " h=" << hex64(h) << "\n\n";
            }
        }

        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;

        if (logHEachBlock) {
            logFile << "[6] H SAU KHI XU LY XONG BLOCK " << blockIndex << ":\n";
            for (int i = 0; i < 8; ++i) {
                logFile << "H[" << i << "] = " << hex64(H[i]) << "\n";
            }
            logFile << "\n";
        }
    }

    stringstream digest;
    for (u64 x : H) {
        digest << hex64(x);
    }
    return digest.str();
}

// ========================= MAIN =========================
int main() {

    string msg;
    cout << "Nhap chuoi can bam: ";
    getline(cin, msg);

    ofstream fout("output.txt");
    if (!fout.is_open()) {
        cerr << "Khong mo duoc file output.txt\n";
        return 1;
    }

    string hash = sha512_trace_to_file(
        msg,
        fout,
        true,   // ghi padding vao file
        true,   // ghi W[16..79] vao file
        true,   // ghi tung round vao file
        true    // ghi H sau moi block vao file
    );

    fout << "========== [7] KET QUA CUOI ==========\n";
    fout << "SHA-512 = " << hash << "\n";
    fout.close();

    cout << "\nSHA-512 = " << hash << "\n";
    cout << "Da ghi cac buoc trung gian vao file output.txt\n";

    return 0;
}