from collections import Counter

import numpy as np


def get_keystream_bytes(key_bytes, n_bytes):
    """
    指定された鍵から、最初のn_bytes分の鍵ストリームを生成して返す
    """
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key_bytes[i % len(key_bytes)]) % 256
        state[i], state[j] = state[j], state[i]

    # PRGA
    i = 0
    j = 0
    keystream = []
    for _ in range(n_bytes):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        t = (state[i] + state[j]) % 256
        keystream.append(state[t])
    return keystream


def simulate_rc4_first_byte_attack(target_plain_byte, num_samples=100000):
    """
    【攻撃1】第1バイト目の分析（デフォルト100,000サンプル）
    秘密鍵を知らなくても、大量の暗号文があれば統計的に平文を推測できることを示す
    """
    print(f"\n【攻撃1】第1バイト分析 - 解析中... ({num_samples}個の暗号パケットを分析中)")

    cipher_first_bytes = []

    for _ in range(num_samples):
        random_key = np.random.randint(0, 256, size=16).tolist()
        stream = get_keystream_bytes(random_key, 1)
        cipher_byte = target_plain_byte ^ stream[0]
        cipher_first_bytes.append(cipher_byte)

    counts = Counter(cipher_first_bytes)
    most_common = counts.most_common(3)

    return most_common


def simulate_rc4_first_byte_attack_large(target_plain_byte, num_samples=10000000):
    """
    【攻撃2】第1バイト目の分析（1000万サンプル）
    サンプル数を大幅に増やすことで、統計的精度を向上させる
    """
    print(f"\n【攻撃2】第1バイト分析（大規模） - 解析中... ({num_samples}個の暗号パケットを分析中)")

    cipher_first_bytes = []

    for _ in range(num_samples):
        random_key = np.random.randint(0, 256, size=16).tolist()
        stream = get_keystream_bytes(random_key, 1)
        cipher_byte = target_plain_byte ^ stream[0]
        cipher_first_bytes.append(cipher_byte)

    counts = Counter(cipher_first_bytes)
    most_common = counts.most_common(3)

    return most_common


def simulate_rc4_second_byte_attack(target_plain_byte, num_samples=100000):
    """
    【攻撃3】第2バイト目の分析（FMS攻撃）
    RC4の第2バイト目に顕著な偏りがあることを利用する
    """
    print(f"\n【攻撃3】第2バイト分析（FMS攻撃） - 解析中... ({num_samples}個の暗号パケットを分析中)")

    cipher_second_bytes = []

    for _ in range(num_samples):
        random_key = np.random.randint(0, 256, size=16).tolist()
        stream = get_keystream_bytes(random_key, 2)
        cipher_byte = target_plain_byte ^ stream[1]
        cipher_second_bytes.append(cipher_byte)

    counts = Counter(cipher_second_bytes)
    most_common = counts.most_common(3)

    return most_common


def simulate_rc4_multi_byte_attack(target_plain_bytes, num_samples=100000):
    """
    【攻撃4】複数バイト同時分析
    複数のバイトを同時に分析することで、復号精度を大幅に向上させる
    target_plain_bytes: リスト例 [65, 66, 67] (ABC)
    """
    num_bytes = len(target_plain_bytes)
    print(f"\n【攻撃4】複数バイト同時分析 - 解析中... ({num_samples}個の暗号パケットを分析中)")

    cipher_sequences = []

    for _ in range(num_samples):
        random_key = np.random.randint(0, 256, size=16).tolist()
        stream = get_keystream_bytes(random_key, num_bytes)
        cipher_seq = tuple(target_plain_bytes[i] ^ stream[i] for i in range(num_bytes))
        cipher_sequences.append(cipher_seq)

    counts = Counter(cipher_sequences)
    most_common = counts.most_common(3)

    return most_common


# ターゲットとなる平文の1文字目 (例: 'A' = 65)
target_char = "A"
target_byte = ord(target_char)

# ========== 攻撃1: 第1バイト分析（100k） ==========
results1 = simulate_rc4_first_byte_attack(target_byte, num_samples=100000)

print("--- 解析結果 ---")
for i, (val, count) in enumerate(results1):
    predicted_char = chr(val) if 32 <= val <= 126 else "?"
    print(f"{i+1}位の候補: '{predicted_char}' (値: {val}, 出現数: {count})")

print(f"正解の平文は '{target_char}' (値: {target_byte}) でした。")
print(f"成功率: {100 * (results1[0][0] == target_byte) / 1:.1f}%")

# ========== 攻撃2: 第1バイト分析（1000万） ==========
results2 = simulate_rc4_first_byte_attack_large(target_byte, num_samples=1000000)

print("\n--- 解析結果 ---")
for i, (val, count) in enumerate(results2):
    predicted_char = chr(val) if 32 <= val <= 126 else "?"
    print(f"{i+1}位の候補: '{predicted_char}' (値: {val}, 出現数: {count})")

print(f"正解の平文は '{target_char}' (値: {target_byte}) でした。")
print(f"成功率: {100 * (results2[0][0] == target_byte) / 1:.1f}%")

# ========== 攻撃3: 第2バイト分析（FMS攻撃） ==========
results3 = simulate_rc4_second_byte_attack(target_byte, num_samples=100000)

print("\n--- 解析結果 ---")
for i, (val, count) in enumerate(results3):
    predicted_char = chr(val) if 32 <= val <= 126 else "?"
    print(f"{i+1}位の候補: '{predicted_char}' (値: {val}, 出現数: {count})")

print(f"正解の平文は '{target_char}' (値: {target_byte}) でした。")
print(f"成功率: {100 * (results3[0][0] == target_byte) / 1:.1f}%")

# ========== 攻撃4: 複数バイト同時分析 ==========
target_plaintext = [65, 66, 67]  # "ABC"
target_plaintext_str = "".join(chr(b) for b in target_plaintext)
results4 = simulate_rc4_multi_byte_attack(target_plaintext, num_samples=100000)

print("\n--- 解析結果 ---")
for i, (seq, count) in enumerate(results4):
    predicted_str = "".join(
        chr(b) if 32 <= b <= 126 else "?" for b in seq
    )
    print(f"{i+1}位の候補: '{predicted_str}' (値: {seq}, 出現数: {count})")

print(f"正解の平文は '{target_plaintext_str}' (値: {target_plaintext}) でした。")
print(f"成功率: {100 * (results4[0][0] == tuple(target_plaintext)) / 1:.1f}%")

# ========== 攻撃成功度の比較 ==========
print("\n\n========== 攻撃手法の比較 ==========")
print(f"【攻撃1】第1バイト分析（100k）: {results1[0][0] == target_byte} → 正解度: {results1[0][1]/100000*100:.2f}%")
print(f"【攻撃2】第1バイト分析（1000万）: {results2[0][0] == target_byte} → 正解度: {results2[0][1]/1000000*100:.2f}%")
print(f"【攻撃3】第2バイト分析（FMS）: {results3[0][0] == target_byte} → 正解度: {results3[0][1]/100000*100:.2f}%")
print(f"【攻撃4】複数バイト（ABC）: {results4[0][0] == tuple(target_plaintext)} → 正解度: {results4[0][1]/100000*100:.2f}%")
