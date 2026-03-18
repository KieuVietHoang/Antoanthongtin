#include <iostream>
#include <vector>
#include <string>
using namespace std;

// In vector
void printVector(const vector<int>& v, const string& name) {
    cout << name << " = [";
    for (size_t i = 0; i < v.size(); i++) {
        cout << v[i];
        if (i != v.size() - 1) cout << ", ";
    }
    cout << "]\n";
}

// KSA
void KSA(vector<int>& S, const vector<int>& K) {
    int N = S.size();
    int j = 0;

    for (int i = 0; i < N; i++) {
        j = (j + S[i] + K[i % K.size()]) % N;
        swap(S[i], S[j]);
    }
}

// PRGA
vector<int> PRGA(vector<int>& S, int length) {
    int N = S.size();
    int i = 0, j = 0;
    vector<int> keystream;

    for (int k = 0; k < length; k++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;
        swap(S[i], S[j]);

        int t = (S[i] + S[j]) % N;
        int key = S[t];
        keystream.push_back(key);
    }

    return keystream;
}

// Mã hóa thành chuỗi
string encryptToText(const string& plaintext, const vector<int>& keystream) {
    string ciphertext = "";

    for (size_t i = 0; i < plaintext.size(); i++) {
        char c = plaintext[i] ^ keystream[i];
        ciphertext += c;
    }

    return ciphertext;
}

int main() {
    vector<int> S = {0,1,2,3,4,5,6,7,8,9};
    vector<int> K = {2,4,1,7};
    string plaintext = "cybersecurity";

    cout << "Plaintext: " << plaintext << "\n";

    KSA(S, K);
    printVector(S, "S sau KSA");

    vector<int> keystream = PRGA(S, plaintext.length());
    printVector(keystream, "Keystream");

    string ciphertext = encryptToText(plaintext, keystream);
    cout << "Ciphertext dang chu: " << ciphertext << "\n";

    return 0;
}