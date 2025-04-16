#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <cmath>

using namespace std;

// Helper function to convert letter to number (0-25)
int charToNum(char c) {
    return tolower(c) - 'a';
}

// Helper function to convert number (0-25) to letter
char numToChar(int n) {
    return static_cast<char>('a' + n);
}

// Helper function for modular arithmetic
int mod(int a, int b) {
    return (a % b + b) % b;
}

// -------------------- Caesar Cipher --------------------
string caesarEncrypt(string plaintext, int shift) {
    string ciphertext = "";
    for (char c : plaintext) {
        if (isalpha(c)) {
            int num = charToNum(c);
            int shiftedNum = mod(num + shift, 26);
            ciphertext += numToChar(shiftedNum);
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

string caesarDecrypt(string ciphertext, int shift) {
    return caesarEncrypt(ciphertext, -shift);
}

// -------------------- Atbash Cipher --------------------
string atbashCipher(string text) {
    string result = "";
    for (char c : text) {
        if (isalpha(c)) {
            result += numToChar(25 - charToNum(c));
        } else {
            result += c;
        }
    }
    return result;
}

// -------------------- Affine Cipher --------------------
// Function to find the modular multiplicative inverse
int modInverse(int a, int m) {
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1; // Inverse doesn't exist
}

string affineEncrypt(string plaintext, int a, int b) {
    string ciphertext = "";
    for (char c : plaintext) {
        if (isalpha(c)) {
            int num = charToNum(c);
            int encryptedNum = mod((a * num + b), 26);
            ciphertext += numToChar(encryptedNum);
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

string affineDecrypt(string ciphertext, int a, int b) {
    int aInverse = modInverse(a, 26);
    if (aInverse == -1) {
        return "Error: Modular inverse of 'a' does not exist.";
    }
    string plaintext = "";
    for (char c : ciphertext) {
        if (isalpha(c)) {
            int num = charToNum(c);
            int decryptedNum = mod((aInverse * (num - b)), 26);
            plaintext += numToChar(decryptedNum);
        } else {
            plaintext += c;
        }
    }
    return plaintext;
}

// -------------------- Vigenere Cipher --------------------
string vigenereEncrypt(string plaintext, string key) {
    string ciphertext = "";
    int keyIndex = 0;
    for (char c : plaintext) {
        if (isalpha(c)) {
            int plainNum = charToNum(c);
            int keyNum = charToNum(key[keyIndex % key.length()]);
            int encryptedNum = mod(plainNum + keyNum, 26);
            ciphertext += numToChar(encryptedNum);
            keyIndex++;
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

string vigenereDecrypt(string ciphertext, string key) {
    string plaintext = "";
    int keyIndex = 0;
    for (char c : ciphertext) {
        if (isalpha(c)) {
            int cipherNum = charToNum(c);
            int keyNum = charToNum(key[keyIndex % key.length()]);
            int decryptedNum = mod(cipherNum - keyNum, 26);
            plaintext += numToChar(decryptedNum);
            keyIndex++;
        } else {
            plaintext += c;
        }
    }
    return plaintext;
}

// -------------------- Gronsfeld Cipher --------------------
string gronsfeldEncrypt(string plaintext, string key) {
    string ciphertext = "";
    int keyIndex = 0;
    for (char c : plaintext) {
        if (isalpha(c)) {
            int plainNum = charToNum(c);
            int keyDigit = key[keyIndex % key.length()] - '0';
            int encryptedNum = mod(plainNum + keyDigit, 26);
            ciphertext += numToChar(encryptedNum);
            keyIndex++;
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

string gronsfeldDecrypt(string ciphertext, string key) {
    string plaintext = "";
    int keyIndex = 0;
    for (char c : ciphertext) {
        if (isalpha(c)) {
            int cipherNum = charToNum(c);
            int keyDigit = key[keyIndex % key.length()] - '0';
            int decryptedNum = mod(cipherNum - keyDigit, 26);
            plaintext += numToChar(decryptedNum);
            keyIndex++;
        } else {
            plaintext += c;
        }
    }
    return plaintext;
}

// -------------------- Beaufort Cipher --------------------
string beaufortEncrypt(string plaintext, string key) {
    string ciphertext = "";
    int keyIndex = 0;
    for (char c : plaintext) {
        if (isalpha(c)) {
            int plainNum = charToNum(c);
            int keyNum = charToNum(key[keyIndex % key.length()]);
            int encryptedNum = mod(keyNum - plainNum, 26);
            ciphertext += numToChar(encryptedNum);
            keyIndex++;
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

string beaufortDecrypt(string ciphertext, string key) {
    string plaintext = "";
    int keyIndex = 0;
    for (char c : ciphertext) {
        if (isalpha(c)) {
            int cipherNum = charToNum(c);
            int keyNum = charToNum(key[keyIndex % key.length()]);
            int decryptedNum = mod(keyNum - cipherNum, 26);
            plaintext += numToChar(decryptedNum);
            keyIndex++;
        } else {
            plaintext += c;
        }
    }
    return plaintext;
}

// -------------------- Autoclave/Running Key Cipher --------------------
string autoclaveEncrypt(string plaintext, string key) {
    string ciphertext = "";
    string currentKey = key;
    for (int i = 0; i < plaintext.length(); ++i) {
        char plainChar = plaintext[i];
        if (isalpha(plainChar)) {
            int plainNum = charToNum(plainChar);
            int keyNum = charToNum(currentKey[i % currentKey.length()]);
            int encryptedNum = mod(plainNum + keyNum, 26);
            ciphertext += numToChar(encryptedNum);
            currentKey += plainChar; // Extend the key with the plaintext character
        } else {
            ciphertext += plainChar;
            currentKey += plainChar; // Keep non-alpha characters in the key as well for alignment
        }
    }
    return ciphertext;
}

string autoclaveDecrypt(string ciphertext, string key) {
    string plaintext = "";
    string currentKey = key;
    for (int i = 0; i < ciphertext.length(); ++i) {
        char cipherChar = ciphertext[i];
        if (isalpha(cipherChar)) {
            int cipherNum = charToNum(cipherChar);
            int keyNum = charToNum(currentKey[i % currentKey.length()]);
            int decryptedNum = mod(cipherNum - keyNum, 26);
            plaintext += numToChar(decryptedNum);
            currentKey += numToChar(decryptedNum); // Extend the key with the decrypted character
        } else {
            plaintext += cipherChar;
            currentKey += cipherChar; // Keep non-alpha characters in the key as well for alignment
        }
    }
    return plaintext;
}

string runningKeyEncrypt(string plaintext, string key) {
    string ciphertext = "";
    int keyIndex = 0;
    for (char c : plaintext) {
        if (isalpha(c)) {
            int plainNum = charToNum(c);
            int keyNum = charToNum(key[keyIndex % key.length()]);
            int encryptedNum = mod(plainNum + keyNum, 26);
            ciphertext += numToChar(encryptedNum);
            keyIndex++;
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

string runningKeyDecrypt(string ciphertext, string key) {
    return vigenereDecrypt(ciphertext, key); // Running key decryption is the same as Vigenere decryption if the key is the running key.
}

// -------------------- Ngram Operations (Example: Bigram Frequency) --------------------
map<string, int> calculateBigramFrequency(string text) {
    map<string, int> frequencyMap;
    for (int i = 0; i < text.length() - 1; ++i) {
        if (isalpha(text[i]) && isalpha(text[i + 1])) {
            string bigram;
            bigram += tolower(text[i]);
            bigram += tolower(text[i + 1]);
            frequencyMap[bigram]++;
        }
    }
    return frequencyMap;
}

// -------------------- Hill Cipher (for block size 2) --------------------
// Function to multiply two 2x2 matrices
vector<vector<int>> multiplyMatrices(const vector<vector<int>>& a, const vector<vector<int>>& b) {
    vector<vector<int>> result = {{0, 0}, {0, 0}};
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j) {
            for (int k = 0; k < 2; ++k) {
                result[i][j] = mod(result[i][j] + a[i][k] * b[k][j], 26);
            }
        }
    }
    return result;
}

// Function to find the determinant of a 2x2 matrix
int determinant(const vector<vector<int>>& matrix) {
    return mod(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0], 26);
}

// Function to find the modular inverse of a 2x2 matrix
vector<vector<int>> inverseMatrix(const vector<vector<int>>& matrix) {
    int det = determinant(matrix);
    int detInverse = modInverse(det, 26);
    if (detInverse == -1) {
        return {{-1, -1}, {-1, -1}}; // Indicate error
    }
    return {
        {mod(matrix[1][1] * detInverse, 26), mod(-matrix[0][1] * detInverse, 26)},
        {mod(-matrix[1][0] * detInverse, 26), mod(matrix[0][0] * detInverse, 26)}
    };
}

string hillEncrypt(string plaintext, const vector<vector<int>>& key) {
    string ciphertext = "";
    for (int i = 0; i < plaintext.length(); i += 2) {
        vector<int> block(2);
        if (i + 1 < plaintext.length()) {
            block[0] = charToNum(plaintext[i]);
            block[1] = charToNum(plaintext[i + 1]);
        } else {
            block[0] = charToNum(plaintext[i]);
            block[1] = 23; // Pad with 'x' if odd length
        }

        vector<vector<int>> plainMatrix = {{block[0]}, {block[1]}};
        vector<vector<int>> keyMatrix = key;
        vector<vector<int>> cipherMatrix = multiplyMatrices(keyMatrix, plainMatrix);

        ciphertext += numToChar(cipherMatrix[0][0]);
        ciphertext += numToChar(cipherMatrix[1][0]);
    }
    return ciphertext;
}

string hillDecrypt(string ciphertext, const vector<vector<int>>& key) {
    vector<vector<int>> invKey = inverseMatrix(key);
    if (invKey[0][0] == -1) {
        return "Error: Key matrix is not invertible.";
    }
    string plaintext = "";
    for (int i = 0; i < ciphertext.length(); i += 2) {
        vector<int> block(2);
        block[0] = charToNum(ciphertext[i]);
        block[1] = charToNum(ciphertext[i + 1]);

        vector<vector<int>> cipherMatrix = {{block[0]}, {block[1]}};
        vector<vector<int>> plainMatrix = multiplyMatrices(invKey, cipherMatrix);

        plaintext += numToChar(plainMatrix[0][0]);
        plaintext += numToChar(plainMatrix[1][0]);
    }
    return plaintext;
}

// -------------------- Rail Fence Cipher --------------------
string railFenceEncrypt(string plaintext, int rails) {
    if (rails <= 1) return plaintext;
    vector<string> fence(rails);
    int rail = 0;
    int direction = 1; // 1 for down, -1 for up

    for (char c : plaintext) {
        fence[rail] += c;
        rail += direction;
        if (rail == rails - 1) direction = -1;
        if (rail == 0) direction = 1;
    }

    string ciphertext = "";
    for (const string& row : fence) {
        ciphertext += row;
    }
    return ciphertext;
}

string railFenceDecrypt(string ciphertext, int rails) {
    if (rails <= 1) return ciphertext;
    vector<string> fence(rails);
    vector<int> railCounts(rails, 0);
    int rail = 0;
    int direction = 1;

    for (int i = 0; i < ciphertext.length(); ++i) {
        railCounts[rail]++;
        rail += direction;
        if (rail == rails - 1) direction = -1;
        if (rail == 0) direction = 1;
    }

    int index = 0;
    for (int i = 0; i < rails; ++i) {
        fence[i] = ciphertext.substr(index, railCounts[i]);
        index += railCounts[i];
    }

    string plaintext = "";
    rail = 0;
    direction = 1;
    vector<int> currentIndices(rails, 0);

    for (int i = 0; i < ciphertext.length(); ++i) {
        plaintext += fence[rail][currentIndices[rail]++];
        rail += direction;
        if (rail == rails - 1) direction = -1;
        if (rail == 0) direction = 1;
    }
    return plaintext;
}

// -------------------- Route Cipher (Columnar Transposition - Simple Route) --------------------
string routeEncrypt(string plaintext, int columns) {
    if (columns <= 0) return plaintext;
    int rows = ceil((double)plaintext.length() / columns);
    vector<vector<char>> grid(rows, vector<char>(columns, ' '));
    int index = 0;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < columns; ++j) {
            if (index < plaintext.length()) {
                grid[i][j] = plaintext[index++];
            }
        }
    }

    string ciphertext = "";
    for (int j = 0; j < columns; ++j) {
        for (int i = 0; i < rows; ++i) {
            if (grid[i][j] != ' ') {
                ciphertext += grid[i][j];
            }
        }
    }
    return ciphertext;
}

string routeDecrypt(string ciphertext, int columns) {
    if (columns <= 0) return ciphertext;
    int rows = ceil((double)ciphertext.length() / columns);
    vector<vector<char>> grid(rows, vector<char>(columns));
    int index = 0;
    for (int j = 0; j < columns; ++j) {
        for (int i = 0; i < rows; ++i) {
            if (index < ciphertext.length()) {
                grid[i][j] = ciphertext[index++];
            }
        }
    }

    string plaintext = "";
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < columns; ++j) {
            plaintext += grid[i][j];
        }
    }
    // Remove trailing spaces if any
    plaintext.erase(remove(plaintext.begin(), plaintext.end(), ' '), plaintext.end());
    return plaintext;
}

// -------------------- Myszkowski Cipher --------------------
string myszkowskiEncrypt(string plaintext, string key) {
    string ciphertext = "";
    int keyLength = key.length();
    int textLength = plaintext.length();
    int rows = ceil((double)textLength / keyLength);
    vector<vector<char>> grid(rows, vector<char>(keyLength, ' '));

    // Fill the grid
    int index = 0;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < keyLength; ++j) {
            if (index < textLength) {
                grid[i][j] = plaintext[index++];
            }
        }
    }

    // Create a map to store the order of columns based on the key
    map<char, vector<int>> keyOrder;
    for (int i = 0; i < keyLength; ++i) {
        keyOrder[key[i]].push_back(i);
    }

    // Read from the grid based on the sorted key
    for (auto const& [keyChar, indices] : keyOrder) {
        for (int colIndex : indices) {
            for (int i = 0; i < rows; ++i) {
                if (grid[i][colIndex] != ' ') {
                    ciphertext += grid[i][colIndex];
                }
            }
        }
    }

    return ciphertext;
}

// Myszkowski decryption is more complex and requires knowing the dimensions and the keyword.
// A full implementation would involve reconstructing the grid. For brevity, I'll skip the decryption here.
// You can find resources online for implementing Myszkowski decryption.

int main() {
    string plaintext = "This is Raghav.G from IOT B";
    string key = "key";
    string gronsfeldKey = "123";
    vector<vector<int>> hillKey = {{2, 3}, {5, 7}};
    int rails = 3;
    int columns = 5;

    cout << "Plaintext: " << plaintext << endl;

    cout << "\n--- Caesar Cipher ---" << endl;
    string caesarEncrypted = caesarEncrypt(plaintext, 3);
    cout << "Encrypted: " << caesarEncrypted << endl;
    cout << "Decrypted: " << caesarDecrypt(caesarEncrypted, 3) << endl;

    cout << "\n--- Atbash Cipher ---" << endl;
    string atbashEncrypted = atbashCipher(plaintext);
    cout << "Encrypted: " << atbashEncrypted << endl;
    cout << "Decrypted: " << atbashCipher(atbashEncrypted) << endl;

    cout << "\n--- Affine Cipher ---" << endl;
    string affineEncrypted = affineEncrypt(plaintext, 7, 3);
    cout << "Encrypted: " << affineEncrypted << endl;
    cout << "Decrypted: " << affineDecrypt(affineEncrypted, 7, 3) << endl;

    cout << "\n--- Vigenere Cipher ---" << endl;
    string vigenereEncrypted = vigenereEncrypt(plaintext, key);
    cout << "Encrypted: " << vigenereEncrypted << endl;
    cout << "Decrypted: " << vigenereDecrypt(vigenereEncrypted, key) << endl;

    cout << "\n--- Gronsfeld Cipher ---" << endl;
    string gronsfeldEncrypted = gronsfeldEncrypt(plaintext, gronsfeldKey);
    cout << "Encrypted: " << gronsfeldEncrypted << endl;
    cout << "Decrypted: " << gronsfeldDecrypt(gronsfeldEncrypted, gronsfeldKey) << endl;

    cout << "\n--- Beaufort Cipher ---" << endl;
    string beaufortEncrypted = beaufortEncrypt(plaintext, key);
    cout << "Encrypted: " << beaufortEncrypted << endl;
    cout << "Decrypted: " << beaufortDecrypt(beaufortEncrypted, key) << endl;

    cout << "\n--- Autoclave Cipher ---" << endl;
    string autoclaveEncrypted = autoclaveEncrypt(plaintext, key);
    cout << "Encrypted: " << autoclaveEncrypted << endl;
    cout << "Decrypted: " << autoclaveDecrypt(autoclaveEncrypted, key) << endl;

    cout << "\n--- Running Key Cipher ---" << endl;
    string runningKeyEncrypted = runningKeyEncrypt(plaintext, "thisistherunningkey");
    cout << "Encrypted: " << runningKeyEncrypted << endl;
    cout << "Decrypted: " << runningKeyDecrypt(runningKeyEncrypted, "thisistherunningkey") << endl;

    cout << "\n--- Ngram Operations (Bigram Frequency) ---" << endl;
    string ngramText = "The quick brown fox jumps over the lazy fox";
    map<string, int> bigramFreq = calculateBigramFrequency(ngramText);
    for (const auto& pair : bigramFreq) {
        cout << pair.first << ": " << pair.second << endl;
    }

    cout << "\n--- Hill Cipher ---" << endl;
    string hillPlaintext = "paym"; // Example plaintext of length 4 (divisible by block size 2)
    string hillEncrypted = hillEncrypt(hillPlaintext, hillKey);
    cout << "Encrypted: " << hillEncrypted << endl;
    cout << "Decrypted: " << hillDecrypt(hillEncrypted, hillKey) << endl;

    cout << "\n--- Rail Fence Cipher ---" << endl;
    string railFenceEncrypted = railFenceEncrypt(plaintext, rails);
    cout << "Encrypted: " << railFenceEncrypted << endl;
    cout << "Decrypted: " << railFenceDecrypt(railFenceEncrypted, rails) << endl;

    cout << "\n--- Route Cipher (Columnar Transposition) ---" << endl;
    string routeEncrypted = routeEncrypt(plaintext, columns);
    cout << "Encrypted: " << routeEncrypted << endl;
    cout << "Decrypted: " << routeDecrypt(routeEncrypted, columns) << endl;

    cout << "\n--- Myszkowski Cipher ---" << endl;
    string myszkowskiEncrypted = myszkowskiEncrypt(plaintext, key);
    cout << "Encrypted: " << myszkowskiEncrypted << endl;
    // Decryption for Myszkowski is not implemented here.

    return 0;
}
