#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <fstream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/crypto.h>

using namespace std;

BIGNUM* hex2bn(const string& hex) {
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

EC_POINT* hex2point(EC_GROUP* group, const string& hex) {
    EC_POINT* point = EC_POINT_new(group);
    EC_POINT_hex2point(group, hex.c_str(), point, NULL);
    return point;
}

void saveFoundKey(const string& filename, BIGNUM* d) {
    ofstream file(filename);
    if (file.is_open()) {
        char* d_hex = BN_bn2hex(d);
        file << d_hex << endl;
        file.close();
        OPENSSL_free(d_hex);
        cout << "\n✅ Zapisano klucz do pliku: " << filename << endl;
    }
}

// Zapis postępu
void saveProgress(const string& filename, BIGNUM* k1, unsigned long long attempts) {
    ofstream file(filename);
    if (file.is_open()) {
        char* k1_hex = BN_bn2hex(k1);
        file << k1_hex << endl;
        file << attempts << endl;
        file.close();
        OPENSSL_free(k1_hex);
    }
}

// Wczytaj postęp
bool loadProgress(const string& filename, BIGNUM* k1, unsigned long long& attempts) {
    ifstream file(filename);
    if (file.is_open()) {
        string k1_hex;
        getline(file, k1_hex);
        file >> attempts;
        file.close();
        
        BN_hex2bn(&k1, k1_hex.c_str());
        return true;
    }
    return false;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_CTX* ctx = BN_CTX_new();

    string pubkey_hex = "04766671d3b6d67717b38a4ef1653ad2e39e695a70d535e996b0825635698fa2338d5d81be10736c67f61aabc6d260caaf65ec8bc6b8ae7b14604cab07665e8db1";
    EC_POINT* expected_pub = hex2point(group, pubkey_hex);




    // ============================================
    // PODPIS 1
    // ============================================
    string r1_hex = "201db779231dcaedc787b90140526e9f9ce3c74e9d73f036b1fa1407c66fcbce";
    string s1_hex = "87ddbd5ca40a0d916b2d88be3581f259352f5ef5b974ad7f7f9cd358c187c131";
    string z1_hex = "689a6b8ea4539162ac06ddfc181c8bc59430b5f9fc5b97bdc71407002350e12e";

    // ============================================
    // PODPIS 2
    // ============================================
    string r2_hex = "a89686f2f65708664fc0a0481ce8d10e87194b05de5aec60197301d6a7c22d06";
    string s2_hex = "4d5f815b46da6e5b73ca9dafc411bb6010e7cc5874ee39e1424fb4f79ab62908";
    string z2_hex = "7f8f2e19355dcfdadd85c4320ace3a211c284e32258842c8573e107da04bcb2a";

    // ============================================
    // PODPIS 3 - DODATKOWY!
    // ============================================
    string r3_hex = "05a4c7a92843580dad6d19b725446b5b379cd9dfaa0b1415fdc56fbcfba79950";
    string s3_hex = "c95730077d0b79281c629f0590f5beeb266b8e9e64a63df14a296bed368a6ecf";
    string z3_hex = "46431004e246659c25d0fe9ab314d5f39b79831f4ae21f880acc1eae4354627f";

    BIGNUM* r1 = hex2bn(r1_hex);
    BIGNUM* s1 = hex2bn(s1_hex);
    BIGNUM* z1 = hex2bn(z1_hex);
    BIGNUM* r2 = hex2bn(r2_hex);
    BIGNUM* s2 = hex2bn(s2_hex);
    BIGNUM* z2 = hex2bn(z2_hex);
    BIGNUM* r3 = hex2bn(r3_hex);
    BIGNUM* s3 = hex2bn(s3_hex);
    BIGNUM* z3 = hex2bn(z3_hex);

    cout << "========================================" << endl;
    cout << "SZUKANIE Z 3 PODPISAMI" << endl;
    cout << "========================================" << endl;
    cout << "Szukam pubkey: " << pubkey_hex << endl << endl;

    // ============================================
    // OBLICZ POCZĄTKOWE k1 Z UKŁADU (k1=k2)
    // ============================================
    BIGNUM* k1 = BN_new();
    BIGNUM* k2 = BN_new();
    BIGNUM* k3 = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* temp2 = BN_new();
    BIGNUM* numerator = BN_new();
    BIGNUM* denominator = BN_new();
    BIGNUM* inv = BN_new();

    // Oblicz d = (s1*z2 - s2*z1) / (s2*r1 - s1*r2)
    BN_mod_mul(temp, s1, z2, order, ctx);
    BN_mod_mul(temp2, s2, z1, order, ctx);
    BN_mod_sub(numerator, temp, temp2, order, ctx);
    
    BN_mod_mul(temp, s2, r1, order, ctx);
    BN_mod_mul(temp2, s1, r2, order, ctx);
    BN_mod_sub(denominator, temp, temp2, order, ctx);
    
    if (BN_is_zero(denominator)) {
        cout << "BŁĄD: Mianownik = 0!" << endl;
        return 1;
    }
    
    BN_mod_inverse(inv, denominator, order, ctx);
    BN_mod_mul(d, numerator, inv, order, ctx);
    
    // Oblicz k1 TYLKO RAZ!
    BN_mod_mul(temp, r1, d, order, ctx);
    BN_mod_add(temp, z1, temp, order, ctx);
    BN_mod_inverse(inv, s1, order, ctx);
    BN_mod_mul(k1, temp, inv, order, ctx);

    // ============================================
    // WCZYTAJ ZAPISANY POSTĘP (JEŚLI ISTNIEJE)
    // ============================================
    unsigned long long attempts = 0;
    string progress_file = "progress.txt";
    
    if (loadProgress(progress_file, k1, attempts)) {
        cout << "✅ Wczytano zapisany postęp!" << endl;
        cout << "   k1 = " << BN_bn2hex(k1) << endl;
        cout << "   Próby: " << attempts << endl << endl;
    } else {
        cout << "Początkowe k1: " << BN_bn2hex(k1) << endl << endl;
    }

    // ============================================
    // GŁÓWNA PĘTLA - PRZESZUKIWANIE
    // ============================================
    BIGNUM* s2_check = BN_new();
    BIGNUM* s3_check = BN_new();
    BIGNUM* rd = BN_new();
    BIGNUM* k_inv = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);

    EC_POINT* calculated_pub = EC_POINT_new(group);

    unsigned long long solutions_found = 0;
    auto start = chrono::high_resolution_clock::now();
    auto last_progress = start;
    auto last_save = start;

    cout << "Rozpoczynam przeszukiwanie..." << endl << endl;

    while (true) {
        attempts++;

        // ============================================
        // OBLICZ d Z PIERWSZEGO RÓWNANIA
        // ============================================
        BN_mod_mul(temp, s1, k1, order, ctx);
        BN_mod_sub(temp, temp, z1, order, ctx);
        BN_mod_inverse(inv, r1, order, ctx);
        BN_mod_mul(d, temp, inv, order, ctx);

        // ============================================
        // OBLICZ k2 I k3
        // ============================================
        BN_mod_mul(rd, r2, d, order, ctx);
        BN_mod_add(temp, z2, rd, order, ctx);
        BN_mod_inverse(inv, s2, order, ctx);
        BN_mod_mul(k2, temp, inv, order, ctx);

        BN_mod_mul(rd, r3, d, order, ctx);
        BN_mod_add(temp, z3, rd, order, ctx);
        BN_mod_inverse(inv, s3, order, ctx);
        BN_mod_mul(k3, temp, inv, order, ctx);

        // ============================================
        // SPRAWDŹ WSZYSTKIE 3 PODPISY
        // ============================================
        BN_mod_inverse(inv, k2, order, ctx);
        BN_mod_mul(rd, r2, d, order, ctx);
        BN_mod_add(temp, z2, rd, order, ctx);
        BN_mod_mul(s2_check, inv, temp, order, ctx);
        
        BN_mod_inverse(inv, k3, order, ctx);
        BN_mod_mul(rd, r3, d, order, ctx);
        BN_mod_add(temp, z3, rd, order, ctx);
        BN_mod_mul(s3_check, inv, temp, order, ctx);

        bool s2_ok = (BN_cmp(s2_check, s2) == 0);
        bool s3_ok = (BN_cmp(s3_check, s3) == 0);

        if (s2_ok && s3_ok) {
            solutions_found++;
            
            // ============================================
            // SPRAWDŹ CZY d GENERUJE POPRAWNY PUBKEY
            // ============================================
            EC_POINT_mul(group, calculated_pub, d, NULL, NULL, ctx);
            
            // SPRAWDŹ CZY PUBKEY LEŻY NA KRZYWEJ
            bool on_curve = EC_POINT_is_on_curve(group, calculated_pub, ctx);
            
            // PORÓWNAJ Z OCZEKIWANYM PUBKEY
            bool pubkey_ok = (EC_POINT_cmp(group, calculated_pub, expected_pub, ctx) == 0);

            // ============================================
            // WYŚWIETLANIE CO 1000 ROZWIĄZAŃ
            // ============================================
            if (solutions_found % 1000 == 0) {
                char* d_hex = BN_bn2hex(d);
                char* k1_hex = BN_bn2hex(k1);
                char* k2_hex = BN_bn2hex(k2);
                char* k3_hex = BN_bn2hex(k3);
                
                auto now = chrono::high_resolution_clock::now();
                auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();
                
                cout << "[#" << solutions_found << "] Próby: " << attempts 
                     << " | Czas: " << elapsed << "s" << endl;
                cout << "  d = " << d_hex << endl;
                cout << "  k1 = " << k1_hex << endl;
                cout << "  k2 = " << k2_hex << endl;
                cout << "  k3 = " << k3_hex << endl;
                cout << "  Podpis 2: " << (s2_ok ? "✅ OK" : "❌ BŁĄD") << endl;
                cout << "  Podpis 3: " << (s3_ok ? "✅ OK" : "❌ BŁĄD") << endl;
                cout << "  Pubkey na krzywej: " << (on_curve ? "✅ TAK" : "❌ NIE") << endl;
                cout << "  Pubkey zgodny:    " << (pubkey_ok ? "✅ ZGADZA SIĘ!" : "❌ NIE PASUJE") << endl << endl;
                
                OPENSSL_free(d_hex);
                OPENSSL_free(k1_hex);
                OPENSSL_free(k2_hex);
                OPENSSL_free(k3_hex);
            }

            // ============================================
            // JAK PUBKEY JEST OK - ZAPISZ I ZATRZYMAJ
            // ============================================
            if (pubkey_ok) {
                auto now = chrono::high_resolution_clock::now();
                auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();

                cout << "\n**************************************************" << endl;
                cout << "*** ZNALEZIONO PRAWDZIWY KLUCZ PRYWATNY! ***" << endl;
                cout << "**************************************************" << endl;
                cout << "Czas: " << elapsed << "s" << endl;
                cout << "Próby: " << attempts << endl;
                cout << "Rozwiązania: " << solutions_found << endl;

                char* d_hex = BN_bn2hex(d);
                char* k1_hex = BN_bn2hex(k1);
                char* k2_hex = BN_bn2hex(k2);
                char* k3_hex = BN_bn2hex(k3);

                cout << "d = " << d_hex << endl;
                cout << "k1 = " << k1_hex << endl;
                cout << "k2 = " << k2_hex << endl;
                cout << "k3 = " << k3_hex << endl;

                // ZAPISZ TYLKO d DO PLIKU
                saveFoundKey("found_private_key.txt", d);
                
                // USUŃ PLIK POSTĘPU (bo już znalezione)
                remove(progress_file.c_str());

                OPENSSL_free(d_hex);
                OPENSSL_free(k1_hex);
                OPENSSL_free(k2_hex);
                OPENSSL_free(k3_hex);

                break; // ZATRZYMAJ SIĘ
            }
        }

        // ============================================
        // PRZEJDŹ DO NASTĘPNEGO k1
        // ============================================
        BN_add(k1, k1, one);
        if (BN_cmp(k1, order) >= 0) {
            BN_sub(k1, k1, order);
        }

        // ============================================
        // ZAPISZ POSTĘP CO MINUTĘ
        // ============================================
        auto now = chrono::high_resolution_clock::now();
        auto save_diff = chrono::duration_cast<chrono::seconds>(now - last_save).count();
        
        if (save_diff >= 60) {  // Co 60 sekund
            saveProgress(progress_file, k1, attempts);
            last_save = now;
            
            // Pokaż że zapisano
            cout << "💾 Zapisano postęp... (próby: " << attempts << ")" << endl;
        }

        // Status co 1M prób
        if (attempts % 1000000 == 0) {
            auto diff = chrono::duration_cast<chrono::seconds>(now - last_progress).count();
            double speed = 1000000.0 / (diff > 0 ? diff : 1);
            
            cout << "\n[STATUS] Próby: " << attempts 
                 << " | Rozwiązań: " << solutions_found 
                 << " | Czas: " << chrono::duration_cast<chrono::seconds>(now - start).count() << "s" 
                 << " | Szybkość: " << fixed << setprecision(0) << speed << " k1/s" << endl << endl;
            
            last_progress = now;
        }
    }

    // Czyszczenie
    BN_free(r1);
    BN_free(s1);
    BN_free(z1);
    BN_free(r2);
    BN_free(s2);
    BN_free(z2);
    BN_free(r3);
    BN_free(s3);
    BN_free(z3);
    BN_free(k1);
    BN_free(k2);
    BN_free(k3);
    BN_free(d);
    BN_free(temp);
    BN_free(temp2);
    BN_free(numerator);
    BN_free(denominator);
    BN_free(inv);
    BN_free(s2_check);
    BN_free(s3_check);
    BN_free(rd);
    BN_free(k_inv);
    BN_free(one);
    EC_POINT_free(calculated_pub);
    EC_POINT_free(expected_pub);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}
